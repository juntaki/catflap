package safefs

import "testing"

// FuzzSplit hardens SafeFS's containment check — the lexical
// root-boundary decision that runs before any syscall, on whatever
// path string an agent's remote_read/remote_stat/remote_write request
// carries. It must never panic. A successful split's components must
// never include an empty string: split relies on filepath.Clean having
// already collapsed things like "a//b" before it slices on the
// separator, and an empty component slipping through would mean that
// normalization step missed a case.
func FuzzSplit(f *testing.F) {
	fs := New([]string{"/tmp/safefs-fuzz-root"})
	seeds := []string{
		"",
		".",
		"/",
		"..",
		"../../etc/passwd",
		"/tmp/safefs-fuzz-root",
		"/tmp/safefs-fuzz-root/x",
		"/tmp/safefs-fuzz-root/../x",
		"\x00",
		"a/b/../../../c",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, path string) {
		_, comps, err := fs.split(path)
		if err != nil {
			return
		}
		for _, c := range comps {
			if c == "" {
				t.Fatalf("split(%q) produced an empty path component: %v", path, comps)
			}
		}
	})
}
