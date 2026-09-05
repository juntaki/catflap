//go:build linux

package safefs

import (
	"path/filepath"
	"strings"
	"testing"
)

// TestOpenat2Parity forces the walk path and compares against the default
// (openat2) path: both must agree on every allow/deny decision.
func TestOpenat2Parity(t *testing.T) {
	root, _ := fixture(t)
	for _, p := range []string{root + "/sub/ok.txt", root + "/linkfile", root + "/escape/outside.txt"} {
		viaDefault, errDefault := openAtRoot(root, relOf(t, root, p), 0, 0, true)
		if errDefault == nil {
			closeFd(viaDefault)
		}
		viaWalk, errWalk := openAtRoot(root, relOf(t, root, p), 0, 0, false)
		if errWalk == nil {
			closeFd(viaWalk)
		}
		if (errDefault == nil) != (errWalk == nil) {
			t.Errorf("%s: openat2=%v walk=%v (must agree)", p, errDefault, errWalk)
		}
	}
}

func relOf(t *testing.T, root, p string) []string {
	t.Helper()
	abs, err := filepath.Abs(p)
	if err != nil {
		t.Fatal(err)
	}
	rel := strings.TrimPrefix(filepath.Clean(abs), filepath.Clean(root)+"/")
	if rel == filepath.Clean(abs) {
		return nil
	}
	return strings.Split(rel, "/")
}
