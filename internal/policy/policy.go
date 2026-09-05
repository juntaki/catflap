package policy

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Policy is a task-scoped capability policy snapshot.
//
// v0.1.1: exec is a structured argv allowlist — there is deliberately no
// shell anywhere in the execution path, so shell metacharacters in arguments
// are inert data. File reads are confined to roots with symlink traversal
// rejected (see ResolveRead).
type Policy struct {
	Name  string        `yaml:"-"`
	TTL   time.Duration `yaml:"-"`
	Tools Tools         `yaml:"-"`
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
	// RealRead holds best-effort symlink-resolved roots for containment
	// checks after EvalSymlinks. Empty entry = fall back to lexical root.
	RealRead   []string `yaml:"-"`
	WriteRoots []string `yaml:"-"`
}

// Default returns a conservative demo policy for `serve` without --policy.
// Note: no file-reading command (cat, …) is listed under exec — file access
// goes through remote_read/remote_stat so filesystem roots always apply.
func Default() *Policy {
	return &Policy{
		Name: "readonly-debug",
		TTL:  15 * time.Minute,
		Tools: Tools{
			Exec: &ExecPolicy{Allow: []ExecRule{
				{Command: "echo", Rest: "any"},
				{Command: "uname", Rest: "any"},
				{Command: "ls", Rest: "any"},
				{Command: "pwd"},
				{Command: "whoami"},
				{Command: "date", Rest: "any"},
			}},
			File: &FilePolicy{Read: []string{"."}, RealRead: []string{mustAbs(".")}},
		},
	}
}

func mustAbs(p string) string {
	a, err := filepath.Abs(p)
	if err != nil {
		return p
	}
	return filepath.Clean(a)
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

// Parse parses YAML policy bytes. The legacy v0.1 string	shell allowlist
// (`exec.commands`) is rejected: it cannot be made safe (metacharacters
// reach `sh`), so it must be migrated to structured `exec.allow`.
func Parse(data []byte) (*Policy, error) {
	var raw struct {
		Name  string `yaml:"name"`
		TTL   string `yaml:"ttl"`
		Tools struct {
			Exec *struct {
				Commands any           `yaml:"commands"`
				Allow    []rawExecRule `yaml:"allow"`
			} `yaml:"exec"`
			File rawFilePolicy `yaml:"file"`
		} `yaml:"tools"`
		Limits *struct {
			TTL string `yaml:"ttl"`
		} `yaml:"limits"`
	}
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parse policy: %w", err)
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
		fp.RealRead = resolveRoots(roots)
	}
	if raw.Tools.File.Write != nil {
		roots, err := normalizeRoots(raw.Tools.File.Write)
		if err != nil {
			return nil, fmt.Errorf("file.write: %w", err)
		}
		fp.WriteRoots = roots
	}
	if len(fp.Read) > 0 || len(fp.WriteRoots) > 0 {
		p.Tools.File = fp
	} else if raw.Tools.File.Read != nil || raw.Tools.File.Write != nil {
		p.Tools.File = fp
	}
	if err := p.Validate(); err != nil {
		return nil, err
	}
	return p, nil
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
				if _, err := filepath.Match(s, ""); err != nil && !errors.Is(err, filepath.ErrBadPattern) {
					return ArgMatcher{}, fmt.Errorf("bad glob %q", s)
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

// resolveRoots cleans roots and resolves symlinks best-effort.
func resolveRoots(roots []string) []string {
	out := make([]string, 0, len(roots))
	for _, r := range roots {
		rr := stripWildcards(strings.TrimSpace(r))
		if rr == "" || rr == "." {
			rr = "."
		}
		abs, err := filepath.Abs(rr)
		if err != nil {
			out = append(out, "")
			continue
		}
		abs = filepath.Clean(abs)
		if real, err := filepath.EvalSymlinks(abs); err == nil {
			abs = filepath.Clean(real)
		}
		out = append(out, abs)
	}
	return out
}

func stripWildcards(r string) string {
	r = strings.TrimSuffix(r, "/**")
	r = strings.TrimSuffix(r, "/*")
	r = strings.TrimSuffix(r, "*")
	return r
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
	return nil
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

// ResolveRead maps a requested path to the file to open, enforcing root
// containment AFTER symlink resolution:
//
//  1. lexical containment of the cleaned absolute path in a root (fast deny),
//  2. Lstat: a symlink as the final component is denied outright,
//  3. EvalSymlinks over the whole path, then containment in the resolved root.
//
// This closes the /workspace/outside->/etc escape. (A fully TOCTOU-proof
// openat/dirfd chain is future work; the window here needs a concurrent
// local writer, which the agent is not.)
func (p *Policy) ResolveRead(path string) (string, error) {
	if p.Tools.File == nil || len(p.Tools.File.Read) == 0 {
		return "", fmt.Errorf("file access is not allowed by policy")
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("bad path: %w", err)
	}
	abs = filepath.Clean(abs)
	rootIdx := -1
	for i, r := range p.Tools.File.Read {
		rr := stripWildcards(strings.TrimSpace(r))
		if rr == "" || rr == "." {
			rr = "."
		}
		rabs, rootErr := filepath.Abs(rr)
		if rootErr != nil {
			continue
		}
		rabs = filepath.Clean(rabs)
		if abs == rabs || strings.HasPrefix(abs, rabs+string(filepath.Separator)) {
			rootIdx = i
			break
		}
	}
	if rootIdx < 0 {
		return "", fmt.Errorf("path not allowed by policy")
	}
	fi, err := os.Lstat(abs)
	if err != nil {
		return "", fmt.Errorf("stat: %w", err)
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return "", fmt.Errorf("symlinks are not allowed")
	}
	resolved, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return "", fmt.Errorf("stat: %w", err)
	}
	resolved = filepath.Clean(resolved)
	realRoot := ""
	if rootIdx < len(p.Tools.File.RealRead) {
		realRoot = p.Tools.File.RealRead[rootIdx]
	}
	if realRoot == "" {
		realRoot, _ = filepath.Abs(stripWildcards(strings.TrimSpace(p.Tools.File.Read[rootIdx])))
		realRoot = filepath.Clean(realRoot)
	}
	if resolved != realRoot && !strings.HasPrefix(resolved, realRoot+string(filepath.Separator)) {
		return "", fmt.Errorf("path escapes allowed roots (symlink traversal denied)")
	}
	return resolved, nil
}
