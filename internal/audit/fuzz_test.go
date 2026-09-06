package audit

import (
	"os"
	"path/filepath"
	"testing"
)

// FuzzVerify hardens the offline audit-chain verifier against a
// tampered or corrupted audit file — the exact input an operator would
// feed it after suspecting foul play, so it must never panic on
// malformed JSONL, truncated lines, or garbage bytes.
func FuzzVerify(f *testing.F) {
	seeds := []string{
		"",
		"\n",
		"{}\n",
		`{"v":1,"task":"agt_x","seq":1,"tool":"task.create","decision":"active","prev":"genesis","hash":"x"}` + "\n",
		"not json\n{{{\n",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, data string) {
		dir := t.TempDir()
		path := filepath.Join(dir, "fuzz.jsonl")
		if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
			t.Skip("could not write fuzz input to disk")
		}
		_, _ = Verify(path)
		// No assertion beyond "does not panic" — Verify's error return
		// already covers every rejection path.
	})
}
