package policy

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/juntaki/catflap/internal/safefs"
)

// SchemaVersion is the only policy schema version Catflap v0.2-A accepts.
// Every policy document MUST declare `version: 1`; unknown versions and
// unknown fields fail closed (INV-5).
const SchemaVersion = 1

// Policy is a task-scoped capability policy snapshot.
//
// v0.1.1: exec is a structured argv allowlist — there is deliberately no
// shell anywhere in the execution path, so shell metacharacters in arguments
// are inert data. File access goes through SafeFS (see ReadFS/WriteFS).
type Policy struct {
	Name   string        `yaml:"-"`
	TTL    time.Duration `yaml:"-"`
	Tools  Tools         `yaml:"-"`
	Limits *Limits       `yaml:"-"`
}

type Tools struct {
	Exec *ExecPolicy `yaml:"-"`
	File *FilePolicy `yaml:"-"`
}

// ExecPolicy is a list of allowed argv vectors.
type ExecPolicy struct {
	Allow []ExecRule
}

// ExecRule pins one executable plus its permitted argument shape.
type ExecRule struct {
	// Command is a bare name (resolved via PATH once, then pinned) or an
	// absolute path. Relative paths containing "/" are rejected.
	Command string
	// Args must match exactly (same length, each element matches).
	Args []ArgMatcher
	// Rest, when "any", permits arbitrary trailing arguments. Safe only
	// for commands that cannot reach outside the task (echo, uname…);
	// never use it for file-reading commands like cat.
	Rest string
}

// ArgMatcher matches a single argv element.
type ArgMatcher struct {
	Literal *string
	Any     bool
	Integer *IntRange
	Choice  []string
	Glob    string // path.Match-style glob over the single element
	HasGlob bool
}

// IntRange constrains a decimal integer argument.
type IntRange struct {
	Min *int64
	Max *int64
}

type FilePolicy struct {
	Read []string `yaml:"-"`
	// Write is nil when file writes are not granted (default deny).
	Write *WriteConfig `yaml:"-"`
}

// WriteConfig grants scoped file writes. All constraints default to deny:
// Create and Overwrite are false unless set, MaxSize bounds content bytes,
// Atomic selects temp+rename replacement.
type WriteConfig struct {
	Roots       []string
	MaxFileSize int64
	Create      bool
	Overwrite   bool
	Atomic      bool
}

// Enabled reports whether this grant can actually authorize any write.
// The legacy roots-only YAML shape (`write: [./foo]`) parses into a
// WriteConfig with Roots set but MaxFileSize/Create/Overwrite all zero,
// which denies every write despite being "configured" — callers deciding
// whether to expose remote_write must agree with WriteFS on this, or the
// tool appears in tools/list yet can never succeed.
func (c *WriteConfig) Enabled() bool {
	return c != nil && len(c.Roots) > 0 && c.MaxFileSize > 0 && (c.Create || c.Overwrite)
}

// Options maps the grant to SafeFS write options.
func (c *WriteConfig) Options() safefs.WriteOptions {
	if c == nil {
		return safefs.WriteOptions{}
	}
	return safefs.WriteOptions{
		MaxSize: c.MaxFileSize, Create: c.Create,
		Overwrite: c.Overwrite, Atomic: c.Atomic,
	}
}

// Default returns a conservative demo policy for `serve` without --policy.
// File-reading commands (cat, ls, …) are deliberately absent: `ls /etc`
// or GNU `date -f` would bypass SafeFS roots, so directory listing belongs
// in a future list_directory tool built on SafeFS — not in exec.
func Default() *Policy {
	return &Policy{
		Name: "readonly-debug",
		TTL:  15 * time.Minute,
		Tools: Tools{
			Exec: &ExecPolicy{Allow: []ExecRule{
				{Command: "echo", Rest: "any"},
				{Command: "uname", Args: []ArgMatcher{{Choice: []string{"-a", "-s", "-r", "-m"}}}},
				{Command: "pwd"},
				{Command: "whoami"},
				{Command: "date"},
			}},
			File: &FilePolicy{Read: []string{"."}},
		},
	}
}

// Load reads a YAML policy file.
func Load(path string) (*Policy, error) {
	//nolint:gosec // reason: path is the operator's --policy CLI flag, never agent input.
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return Parse(data)
}

// Parse parses YAML policy bytes under schema v1. Decoding is strict:
// unknown fields anywhere in the document fail closed (INV-5), as do
// missing or unknown schema versions. The legacy v0.1 shell-string
// allowlist (`exec.commands`) is rejected outright.
func Parse(data []byte) (*Policy, error) {
	var raw struct {
		Version *int   `yaml:"version"`
		Name    string `yaml:"name"`
		TTL     string `yaml:"ttl"`
		Tools   struct {
			Exec *struct {
				Commands any           `yaml:"commands"`
				Allow    []rawExecRule `yaml:"allow"`
			} `yaml:"exec"`
			File rawFilePolicy `yaml:"file"`
		} `yaml:"tools"`
		Limits *rawLimits `yaml:"limits"`
	}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&raw); err != nil {
		return nil, fmt.Errorf("parse policy: %w", err)
	}
	// Strict parsing must also reject a second YAML document (`---`
	// separated): otherwise "unknown fields fail closed" is only true of
	// the first document, and trailing content is silently ignored.
	var extra any
	switch derr := dec.Decode(&extra); {
	case derr == nil:
		return nil, fmt.Errorf("parse policy: unexpected second document")
	case errors.Is(derr, io.EOF):
		// only document present, as expected
	default:
		return nil, fmt.Errorf("parse policy: %w", derr)
	}
	if raw.Version == nil {
		return nil, fmt.Errorf("policy version is required (expected `version: %d`)", SchemaVersion)
	}
	if *raw.Version != SchemaVersion {
		return nil, fmt.Errorf("unsupported policy version %d (expected %d)", *raw.Version, SchemaVersion)
	}
	p := &Policy{Name: raw.Name}
	ttlRaw := raw.TTL
	if raw.Limits != nil && raw.Limits.TTL != "" {
		ttlRaw = raw.Limits.TTL
	}
	if ttlRaw != "" {
		d, err := time.ParseDuration(ttlRaw)
		if err != nil {
			return nil, fmt.Errorf("invalid ttl %q: %w", ttlRaw, err)
		}
		p.TTL = d
	}
	if p.TTL == 0 {
		p.TTL = 15 * time.Minute
	}
	if raw.Limits != nil {
		lim, err := compileLimits(raw.Limits)
		if err != nil {
			return nil, err
		}
		p.Limits = lim
	}
	if raw.Tools.Exec != nil {
		if raw.Tools.Exec.Commands != nil {
			return nil, fmt.Errorf("exec.commands was removed in v0.1.1: shell-string allowlists permit arbitrary command injection; migrate to structured exec.allow ({command, args})")
		}
		ep := &ExecPolicy{}
		for i, r := range raw.Tools.Exec.Allow {
			rule, err := r.compile()
			if err != nil {
				return nil, fmt.Errorf("exec.allow[%d]: %w", i, err)
			}
			ep.Allow = append(ep.Allow, rule)
		}
		p.Tools.Exec = ep
	}
	fp := &FilePolicy{}
	if raw.Tools.File.Read != nil {
		roots, err := normalizeRoots(raw.Tools.File.Read)
		if err != nil {
			return nil, fmt.Errorf("file.read: %w", err)
		}
		fp.Read = roots
	}
	if raw.Tools.File.Write != nil {
		wc, err := parseWrite(raw.Tools.File.Write)
		if err != nil {
			return nil, fmt.Errorf("file.write: %w", err)
		}
		fp.Write = wc
	}
	if len(fp.Read) > 0 || fp.Write != nil {
		p.Tools.File = fp
	} else if raw.Tools.File.Read != nil || raw.Tools.File.Write != nil {
		p.Tools.File = fp
	}
	if err := p.Validate(); err != nil {
		return nil, err
	}
	return p, nil
}

type rawLimits struct {
	TTL string `yaml:"ttl"`
	// All limits below are optional; omitted fields take hard built-in
	// defaults (DefaultLimits), never zero.
	MaxConcurrentCalls *int   `yaml:"max_concurrent_calls"`
	MaxExecDuration    string `yaml:"max_exec_duration"`
	MaxStdoutBytes     *int64 `yaml:"max_stdout_bytes"`
	MaxStderrBytes     *int64 `yaml:"max_stderr_bytes"`
	MaxReadBytes       *int64 `yaml:"max_read_bytes"`
}

// Limits bounds per-task resource use. Every field has a hard built-in
// ceiling even when the policy omits it (see DefaultLimits).
type Limits struct {
	MaxConcurrentCalls int
	MaxExecDuration    time.Duration
	MaxStdoutBytes     int64
	MaxStderrBytes     int64
	MaxReadBytes       int64
}

// DefaultLimits returns the hard built-in bounds applied when the policy
// omits a limit. Resource exhaustion fails the operation; allocation is
// never unbounded.
func DefaultLimits() Limits {
	return Limits{
		MaxConcurrentCalls: 4,
		MaxExecDuration:    2 * time.Minute,
		MaxStdoutBytes:     256 << 10,
		MaxStderrBytes:     64 << 10,
		MaxReadBytes:       256 << 10,
	}
}

// EffectiveLimits overlays the policy's limits on the built-in defaults.
// Nil policy or nil Limits yields the defaults.
func (p *Policy) EffectiveLimits() Limits {
	lim := DefaultLimits()
	if p == nil || p.Limits == nil {
		return lim
	}
	l := p.Limits
	if l.MaxConcurrentCalls > 0 {
		lim.MaxConcurrentCalls = l.MaxConcurrentCalls
	}
	if l.MaxExecDuration > 0 {
		lim.MaxExecDuration = l.MaxExecDuration
	}
	if l.MaxStdoutBytes > 0 {
		lim.MaxStdoutBytes = l.MaxStdoutBytes
	}
	if l.MaxStderrBytes > 0 {
		lim.MaxStderrBytes = l.MaxStderrBytes
	}
	if l.MaxReadBytes > 0 {
		lim.MaxReadBytes = l.MaxReadBytes
	}
	return lim
}

// compileLimits validates a limits section. Every bound has a hard range;
// omitted fields take built-in defaults at use time (EffectiveLimits).
func compileLimits(raw *rawLimits) (*Limits, error) {
	lim := &Limits{}
	if raw.MaxConcurrentCalls != nil {
		n := *raw.MaxConcurrentCalls
		if n < 1 || n > 64 {
			return nil, fmt.Errorf("limits.max_concurrent_calls must be within [1, 64]")
		}
		lim.MaxConcurrentCalls = n
	}
	if raw.MaxExecDuration != "" {
		d, err := time.ParseDuration(raw.MaxExecDuration)
		if err != nil || d < time.Second || d > 30*time.Minute {
			return nil, fmt.Errorf("limits.max_exec_duration must be a duration within [1s, 30m]")
		}
		lim.MaxExecDuration = d
	}
	for _, field := range []struct {
		name string
		v    *int64
		dst  *int64
	}{
		{"max_stdout_bytes", raw.MaxStdoutBytes, &lim.MaxStdoutBytes},
		{"max_stderr_bytes", raw.MaxStderrBytes, &lim.MaxStderrBytes},
		{"max_read_bytes", raw.MaxReadBytes, &lim.MaxReadBytes},
	} {
		if field.v == nil {
			continue
		}
		// Transport contract: JSON string escaping expands worst-case 6x
		// (control bytes → \uXXXX), and stdout+stderr share one result
		// frame while read/write travel alone. 256KiB content + 64KiB
		// stderr keeps every fully-adversarial payload inside the 2MiB
		// frame with margin — so a valid policy is always executable.
		// Larger payloads need chunked tools (future), not larger limits.
		ceiling := int64(256 << 10)
		if field.name == "max_stderr_bytes" {
			ceiling = 64 << 10
		}
		if *field.v <= 0 || *field.v > ceiling {
			return nil, fmt.Errorf("limits.%s must be within (0, %d]", field.name, ceiling)
		}
		*field.dst = *field.v
	}
	return lim, nil
}

type rawExecRule struct {
	Command string `yaml:"command"`
	Args    []any  `yaml:"args"`
	Rest    string `yaml:"rest"`
}

func (r rawExecRule) compile() (ExecRule, error) {
	if strings.TrimSpace(r.Command) == "" {
		return ExecRule{}, fmt.Errorf("command is required")
	}
	if strings.Contains(r.Command, "/") && !filepath.IsAbs(r.Command) {
		return ExecRule{}, fmt.Errorf("command %q: relative paths with '/' are rejected (use a bare name or absolute path)", r.Command)
	}
	rule := ExecRule{Command: strings.TrimSpace(r.Command), Rest: strings.TrimSpace(r.Rest)}
	if rule.Rest != "" && rule.Rest != "any" {
		return ExecRule{}, fmt.Errorf("rest must be \"any\" if set")
	}
	for i, a := range r.Args {
		m, err := compileMatcher(a)
		if err != nil {
			return ExecRule{}, fmt.Errorf("args[%d]: %w", i, err)
		}
		rule.Args = append(rule.Args, m)
	}
	if len(rule.Args) > 64 {
		return ExecRule{}, fmt.Errorf("too many arg matchers (max 64)")
	}
	return rule, nil
}

func compileMatcher(a any) (ArgMatcher, error) {
	switch t := a.(type) {
	case string:
		s := t
		return ArgMatcher{Literal: &s}, nil
	case map[string]any:
		if len(t) != 1 {
			return ArgMatcher{}, fmt.Errorf("matcher must have exactly one key, got %d", len(t))
		}
		for k, v := range t {
			switch k {
			case "any":
				b, ok := v.(bool)
				if !ok || !b {
					return ArgMatcher{}, fmt.Errorf("{any:} must be true")
				}
				return ArgMatcher{Any: true}, nil
			case "integer":
				r := &IntRange{}
				if v != nil {
					mm, ok := v.(map[string]any)
					if !ok {
						return ArgMatcher{}, fmt.Errorf("integer takes a mapping with min/max")
					}
					for key, val := range mm {
						n, err := toInt64(val)
						if err != nil {
							return ArgMatcher{}, fmt.Errorf("integer.%s: %w", key, err)
						}
						switch key {
						case "min":
							r.Min = &n
						case "max":
							r.Max = &n
						default:
							return ArgMatcher{}, fmt.Errorf("unknown integer key %q", key)
						}
					}
				}
				return ArgMatcher{Integer: r}, nil
			case "choice":
				list, ok := v.([]any)
				if !ok || len(list) == 0 {
					return ArgMatcher{}, fmt.Errorf("choice takes a non-empty list")
				}
				var out []string
				for _, e := range list {
					s, ok := e.(string)
					if !ok {
						return ArgMatcher{}, fmt.Errorf("choice elements must be strings")
					}
					out = append(out, s)
				}
				return ArgMatcher{Choice: out}, nil
			case "match":
				s, ok := v.(string)
				if !ok || s == "" {
					return ArgMatcher{}, fmt.Errorf("match takes a non-empty glob string")
				}
				if _, err := filepath.Match(s, ""); err != nil {
					return ArgMatcher{}, fmt.Errorf("bad glob %q: %w", s, err)
				}
				return ArgMatcher{Glob: s, HasGlob: true}, nil
			default:
				return ArgMatcher{}, fmt.Errorf("unknown matcher %q (any|integer|choice|match)", k)
			}
		}
	}
	return ArgMatcher{}, fmt.Errorf("unsupported matcher of type %T", a)
}

func toInt64(v any) (int64, error) {
	switch t := v.(type) {
	case int:
		return int64(t), nil
	case int64:
		return t, nil
	case float64:
		if t != float64(int64(t)) {
			return 0, fmt.Errorf("not an integer: %v", v)
		}
		return int64(t), nil
	case string:
		return strconv.ParseInt(strings.TrimSpace(t), 10, 64)
	default:
		return 0, fmt.Errorf("not an integer: %v", v)
	}
}

type rawFilePolicy struct {
	Read  any `yaml:"read,omitempty"`
	Write any `yaml:"write,omitempty"`
}

func normalizeRoots(v any) ([]string, error) {
	switch t := v.(type) {
	case []any:
		var out []string
		for _, e := range t {
			s, ok := e.(string)
			if !ok {
				return nil, fmt.Errorf("root must be a string, got %T", e)
			}
			out = append(out, s)
		}
		return out, nil
	case map[string]any:
		rv, ok := t["roots"]
		if !ok {
			return nil, fmt.Errorf("expected {roots: [...]}")
		}
		list, ok := rv.([]any)
		if !ok {
			return nil, fmt.Errorf("roots must be a list")
		}
		var out []string
		for _, e := range list {
			s, ok := e.(string)
			if !ok {
				return nil, fmt.Errorf("root must be a string")
			}
			out = append(out, s)
		}
		return out, nil
	default:
		return nil, fmt.Errorf("unsupported roots value of type %T", v)
	}
}

// parseWrite parses the file.write grant. Two forms:
//
//	file:
//	  write: [/workspace/**]            # legacy roots-only (all ops denied)
//	  write:
//	    roots: [/workspace/**]
//	    max_file_size: 1048576
//	    create: true
//	    overwrite: false
//	    atomic: true
//
// Unknown mapping keys fail closed. Omitted constraints deny.
func parseWrite(v any) (*WriteConfig, error) {
	wc := &WriteConfig{Atomic: true}
	switch t := v.(type) {
	case []any:
		roots, err := normalizeRoots(v)
		if err != nil {
			return nil, err
		}
		wc.Roots = roots
		return wc, nil
	case map[string]any:
		for key, val := range t {
			switch key {
			case "roots":
				roots, err := normalizeRoots(val)
				if err != nil {
					return nil, err
				}
				wc.Roots = roots
			case "max_file_size":
				n, err := toInt64(val)
				if err != nil {
					return nil, fmt.Errorf("max_file_size: %w", err)
				}
				wc.MaxFileSize = n
			case "create":
				b, ok := val.(bool)
				if !ok {
					return nil, fmt.Errorf("create must be a boolean")
				}
				wc.Create = b
			case "overwrite":
				b, ok := val.(bool)
				if !ok {
					return nil, fmt.Errorf("overwrite must be a boolean")
				}
				wc.Overwrite = b
			case "atomic":
				b, ok := val.(bool)
				if !ok {
					return nil, fmt.Errorf("atomic must be a boolean")
				}
				wc.Atomic = b
			default:
				return nil, fmt.Errorf("unknown file.write key %q", key)
			}
		}
		return wc, nil
	default:
		return nil, fmt.Errorf("unsupported write value of type %T", v)
	}
}

func (p *Policy) Validate() error {
	if p.Name == "" {
		p.Name = "default"
	}
	if p.TTL <= 0 {
		return fmt.Errorf("ttl must be positive")
	}
	if p.TTL > 24*time.Hour {
		return fmt.Errorf("ttl must not exceed 24h")
	}
	if p.Tools.Exec != nil {
		seen := map[string]bool{}
		for _, r := range p.Tools.Exec.Allow {
			if seen[r.Command] && len(r.Args) == 0 && r.Rest == "" {
				return fmt.Errorf("duplicate exec rule for %q", r.Command)
			}
			seen[r.Command] = true
		}
	}
	if p.Tools.File != nil && p.Tools.File.Write != nil {
		wc := p.Tools.File.Write
		if len(wc.Roots) == 0 {
			return fmt.Errorf("file.write.roots is required when file.write is granted")
		}
		if wc.MaxFileSize < 0 || wc.MaxFileSize > 256<<10 {
			return fmt.Errorf("file.write.max_file_size must be within [0, 256KiB] (transport frame contract)")
		}
	}
	return nil
}

// ReadFS builds the SafeFS for file reads (nil when reads are not granted).
func (p *Policy) ReadFS() *safefs.FS {
	if p.Tools.File == nil || len(p.Tools.File.Read) == 0 {
		return nil
	}
	return safefs.New(p.Tools.File.Read)
}

// WriteFS builds the SafeFS for file writes (nil when writes are not
// granted — the default).
func (p *Policy) WriteFS() *safefs.FS {
	if p.Tools.File == nil || !p.Tools.File.Write.Enabled() {
		return nil
	}
	return safefs.New(p.Tools.File.Write.Roots)
}

// canonicalPolicy is the deterministic JSON envelope for Canonical.
// Field order is fixed by the struct; maps are never used. This envelope is
// part of the v1 contract: the same authorization semantics MUST produce
// the same bytes regardless of YAML formatting, comments, or key order.
type canonicalPolicy struct {
	Version int             `json:"version"`
	Name    string          `json:"name"`
	TTLns   int64           `json:"ttl_ns"`
	Limits  canonicalLimits `json:"limits"`
	Exec    []canonicalRule `json:"exec,omitempty"`
	Read    []string        `json:"read,omitempty"`
	Write   *canonicalWrite `json:"write,omitempty"`
}

type canonicalLimits struct {
	MaxConcurrentCalls int   `json:"max_concurrent_calls"`
	MaxExecDurationNs  int64 `json:"max_exec_duration_ns"`
	MaxStdoutBytes     int64 `json:"max_stdout_bytes"`
	MaxStderrBytes     int64 `json:"max_stderr_bytes"`
	MaxReadBytes       int64 `json:"max_read_bytes"`
}

type canonicalWrite struct {
	Roots       []string `json:"roots"`
	MaxFileSize int64    `json:"max_file_size"`
	Create      bool     `json:"create,omitempty"`
	Overwrite   bool     `json:"overwrite,omitempty"`
	Atomic      bool     `json:"atomic,omitempty"`
}

type canonicalRule struct {
	Command string             `json:"command"`
	Args    []canonicalMatcher `json:"args,omitempty"`
	Rest    string             `json:"rest,omitempty"`
}

type canonicalMatcher struct {
	Literal *string   `json:"literal,omitempty"`
	Any     bool      `json:"any,omitempty"`
	Integer *IntRange `json:"integer,omitempty"`
	Choice  []string  `json:"choice,omitempty"`
	Match   string    `json:"match,omitempty"`
}

// Canonical returns the deterministic byte identity of the policy's
// authorization semantics: cleaned roots, compiled-equivalent matchers,
// TTL in nanoseconds. Formatting-independent by construction.
func (p *Policy) Canonical() []byte {
	lim := p.EffectiveLimits()
	cp := canonicalPolicy{
		Version: SchemaVersion, Name: p.Name, TTLns: int64(p.TTL),
		Limits: canonicalLimits{
			MaxConcurrentCalls: lim.MaxConcurrentCalls,
			MaxExecDurationNs:  int64(lim.MaxExecDuration),
			MaxStdoutBytes:     lim.MaxStdoutBytes,
			MaxStderrBytes:     lim.MaxStderrBytes,
			MaxReadBytes:       lim.MaxReadBytes,
		},
	}
	if p.Tools.Exec != nil {
		for _, r := range p.Tools.Exec.Allow {
			cr := canonicalRule{Command: strings.TrimSpace(r.Command), Rest: strings.TrimSpace(r.Rest)}
			for _, m := range r.Args {
				cm := canonicalMatcher{Any: m.Any, Integer: m.Integer, Choice: m.Choice}
				if m.Literal != nil {
					s := *m.Literal
					cm.Literal = &s
				}
				if m.HasGlob {
					cm.Match = m.Glob
				}
				cr.Args = append(cr.Args, cm)
			}
			cp.Exec = append(cp.Exec, cr)
		}
	}
	if p.Tools.File != nil {
		for _, root := range p.Tools.File.Read {
			cp.Read = append(cp.Read, filepath.Clean(root))
		}
		if wc := p.Tools.File.Write; wc != nil {
			cw := &canonicalWrite{
				MaxFileSize: wc.MaxFileSize, Create: wc.Create,
				Overwrite: wc.Overwrite, Atomic: wc.Atomic,
			}
			for _, root := range wc.Roots {
				cw.Roots = append(cw.Roots, filepath.Clean(root))
			}
			cp.Write = cw
		}
	}
	raw, _ := json.Marshal(cp) //nolint:errchkjson // reason: struct of strings/ints/slices only — no maps, interfaces, or Marshalers — so encoding cannot fail.
	return raw
}

// CanonicalHash is the full hex SHA-256 over Canonical. Capabilities and
// audit records carry a short prefix of this hash as the policy identity:
// equal semantics hash equal, whatever the YAML looked like.
func (p *Policy) CanonicalHash() string {
	sum := sha256.Sum256(p.Canonical())
	return hex.EncodeToString(sum[:])
}

// MatchExec checks command+argv against the structured allowlist and returns
// the pinned absolute executable path. No shell is ever involved, so
// metacharacters in argv are inert.
func (p *Policy) MatchExec(command string, argv []string) (string, bool) {
	if p.Tools.Exec == nil {
		return "", false
	}
	command = strings.TrimSpace(command)
	if command == "" || strings.ContainsAny(command, "\x00\n") {
		return "", false
	}
	if len(argv) > 64 {
		return "", false
	}
	for _, a := range argv {
		if len(a) > 4096 {
			return "", false
		}
	}
	for i := range p.Tools.Exec.Allow {
		rule := &p.Tools.Exec.Allow[i]
		if !sameExecutable(rule.Command, command) {
			continue
		}
		if !matchArgs(rule, argv) {
			continue
		}
		exe, err := rule.resolve()
		if err != nil {
			continue // executable not present on this machine: deny
		}
		return exe, true
	}
	return "", false
}

// sameExecutable compares the requested command to a rule's command by base
// name when the rule is bare, or by exact path when absolute.
func sameExecutable(ruleCmd, got string) bool {
	if filepath.IsAbs(ruleCmd) {
		return filepath.Clean(got) == filepath.Clean(ruleCmd)
	}
	base := got
	if i := strings.LastIndex(got, "/"); i >= 0 {
		base = got[i+1:]
	}
	return base == ruleCmd
}

// resolve maps the rule command to an absolute executable path.
// Bare names go through PATH at call time: the server's PATH is
// operator-controlled (never agent-controlled), and looking up per call
// avoids pinning a stale path. Absolute paths must exist and be executable.
func (r *ExecRule) resolve() (string, error) {
	if filepath.IsAbs(r.Command) {
		exe := filepath.Clean(r.Command)
		fi, err := os.Stat(exe)
		if err != nil || fi.IsDir() || fi.Mode().Perm()&0o111 == 0 {
			return "", fmt.Errorf("not executable: %s", r.Command)
		}
		return exe, nil
	}
	p, err := exec.LookPath(r.Command)
	if err != nil {
		return "", err
	}
	abs, err := filepath.Abs(p)
	if err != nil {
		return "", err
	}
	return filepath.Clean(abs), nil
}

func matchArgs(rule *ExecRule, argv []string) bool {
	if len(argv) < len(rule.Args) {
		return false
	}
	if rule.Rest != "any" && len(argv) != len(rule.Args) {
		return false
	}
	for i, m := range rule.Args {
		if !m.match(argv[i]) {
			return false
		}
	}
	return true
}

func (m ArgMatcher) match(arg string) bool {
	switch {
	case m.Literal != nil:
		return arg == *m.Literal
	case m.Any:
		return true
	case m.Integer != nil:
		n, err := strconv.ParseInt(strings.TrimSpace(arg), 10, 64)
		if err != nil {
			return false
		}
		if m.Integer.Min != nil && n < *m.Integer.Min {
			return false
		}
		if m.Integer.Max != nil && n > *m.Integer.Max {
			return false
		}
		return true
	case m.Choice != nil:
		for _, c := range m.Choice {
			if arg == c {
				return true
			}
		}
		return false
	case m.HasGlob:
		ok, err := filepath.Match(m.Glob, arg)
		return err == nil && ok
	}
	return false
}
