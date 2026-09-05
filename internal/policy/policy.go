package policy

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Policy is a task-scoped capability policy snapshot.
// v0.1 supports exec command allowlists and file read roots.
// Network restrictions, write paths and specialized adapters land in v0.2+.
type Policy struct {
	Name  string        `yaml:"name"`
	TTL   time.Duration `yaml:"-"`
	TTLRaw string       `yaml:"ttl,omitempty"`

	Tools Tools `yaml:"tools"`
}

type Tools struct {
	Exec *ExecPolicy `yaml:"exec,omitempty"`
	File *FilePolicy `yaml:"file,omitempty"`
}

type ExecPolicy struct {
	Commands []string `yaml:"commands"`
}

type FilePolicy struct {
	// Flat form:   file: { read: [...], write: [...] }
	Read []string `yaml:"read,omitempty"`
	// Nested form: file: { read: { roots: [...] } } — normalized on load.
	ReadRoots  []string `yaml:"-"`
	WriteRoots []string `yaml:"-"`
}

type rawFilePolicy struct {
	Read  any `yaml:"read,omitempty"`
	Write any `yaml:"write,omitempty"`
}

type rawRoots struct {
	Roots []string `yaml:"roots"`
}

// Default returns a conservative demo policy for `serve` without --policy.
func Default() *Policy {
	return &Policy{
		Name: "readonly-debug",
		TTL:  15 * time.Minute,
		Tools: Tools{
			Exec: &ExecPolicy{Commands: []string{
				"echo *",
				"uname *",
				"ls *",
				"cat *",
				"pwd",
				"whoami",
			}},
			File: &FilePolicy{Read: []string{".", "/tmp"}},
		},
	}
}

// Load reads a YAML policy file.
func Load(path string) (*Policy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return Parse(data)
}

// Parse parses YAML policy bytes.
func Parse(data []byte) (*Policy, error) {
	var raw struct {
		Name  string `yaml:"name"`
		TTL   string `yaml:"ttl"`
		Tools struct {
			Exec *ExecPolicy   `yaml:"exec"`
			File rawFilePolicy `yaml:"file"`
		} `yaml:"tools"`
		Limits *struct {
			TTL string `yaml:"ttl"`
		} `yaml:"limits"`
	}
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parse policy: %w", err)
	}
	p := &Policy{Name: raw.Name, Tools: Tools{Exec: raw.Tools.Exec}}
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
		p.TTLRaw = ttlRaw
	}
	if p.TTL == 0 {
		p.TTL = 15 * time.Minute
	}
	fp := &FilePolicy{}
	if raw.Tools.File.Read != nil {
		roots, err := normalizeRoots(raw.Tools.File.Read)
		if err != nil {
			return nil, fmt.Errorf("file.read: %w", err)
		}
		fp.Read = roots
		fp.ReadRoots = roots
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
	return nil
}

// AllowExec reports whether cmd matches the exec allowlist.
// Patterns use shell-file glob semantics per whitespace-separated field is
// overkill for v0.1: match the whole command string with path.Match, plus
// a trailing " *" prefix shortcut. Empty allowlist denies everything.
func (p *Policy) AllowExec(cmd string) bool {
	if p.Tools.Exec == nil {
		return false
	}
	cmd = strings.TrimSpace(cmd)
	if cmd == "" {
		return false
	}
	for _, pat := range p.Tools.Exec.Commands {
		if MatchCommand(pat, cmd) {
			return true
		}
	}
	return false
}

// MatchCommand matches a full command string against an allowlist pattern.
// Supported forms:
//   - exact string ("pwd")
//   - glob over the whole string ("journalctl *", "python /opt/jobs/*")
//
// Matching is quote-insensitive: single/double quotes are stripped from both
// sides first, so a policy author can write `systemctl status '*'` and an
// agent sending `systemctl status myapp` still matches. `*` spans separators
// (unlike filepath.Match), so `cat *` covers absolute paths too.
func MatchCommand(pattern, cmd string) bool {
	pattern = stripQuotes(strings.TrimSpace(pattern))
	cmd = stripQuotes(strings.TrimSpace(cmd))
	if pattern == "" || cmd == "" {
		return false
	}
	if !strings.ContainsAny(pattern, "*?[") {
		return pattern == cmd
	}
	re, err := globToRegex(pattern)
	if err != nil {
		return false
	}
	return re.MatchString(cmd)
}

func stripQuotes(s string) string {
	return strings.Map(func(r rune) rune {
		if r == '\'' || r == '"' {
			return -1
		}
		return r
	}, s)
}

var regexMeta = regexp.MustCompile(`[.+()|^$\\{}]`)

// globToRegex translates a command glob to an anchored regex.
// `*` -> `.*`, `?` -> `.`, `[...]` classes pass through.
func globToRegex(glob string) (*regexp.Regexp, error) {
	var b strings.Builder
	b.WriteString("^")
	for i := 0; i < len(glob); i++ {
		c := glob[i]
		switch c {
		case '*':
			b.WriteString(".*")
		case '?':
			b.WriteString(".")
		case '[':
			j := i + 1
			if j < len(glob) && (glob[j] == '!' || glob[j] == '^') {
				j++
			}
			if j < len(glob) && glob[j] == ']' {
				j++
			}
			for j < len(glob) && glob[j] != ']' {
				j++
			}
			if j >= len(glob) {
				b.WriteString("\\[")
			} else {
				inner := glob[i+1 : j]
				inner = strings.Replace(inner, "\\", "\\\\", -1)
				if strings.HasPrefix(inner, "!") {
					inner = "^" + inner[1:]
				}
				b.WriteString("[" + inner + "]")
				i = j
			}
		default:
			b.WriteString(regexMeta.ReplaceAllString(string([]byte{c}), `\$0`))
		}
	}
	b.WriteString("$")
	return regexp.Compile(b.String())
}

// AllowRead reports whether path may be read under the file read roots.
// Empty roots deny everything. "**" suffix and "*" are treated as prefix
// wildcards; otherwise the root itself and everything below it is allowed.
func (p *Policy) AllowRead(path string) bool {
	if p.Tools.File == nil {
		return false
	}
	return withinAnyRoot(path, p.Tools.File.Read)
}

func withinAnyRoot(path string, roots []string) bool {
	abs, err := filepath.Abs(path)
	if err != nil {
		return false
	}
	abs = filepath.Clean(abs)
	for _, r := range roots {
		rr := strings.TrimSpace(r)
		rr = strings.TrimSuffix(rr, "/**")
		rr = strings.TrimSuffix(rr, "/*")
		rr = strings.TrimSuffix(rr, "*")
		if rr == "" || rr == "." {
			ra, _ := filepath.Abs(".")
			if abs == ra || strings.HasPrefix(abs, ra+string(filepath.Separator)) {
				return true
			}
			continue
		}
		rabs, err := filepath.Abs(rr)
		if err != nil {
			continue
		}
		rabs = filepath.Clean(rabs)
		if abs == rabs || strings.HasPrefix(abs, rabs+string(filepath.Separator)) {
			return true
		}
	}
	return false
}
