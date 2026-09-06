package rpc

import (
	"bufio"
	"bytes"
	"testing"
)

// FuzzReadRequest hardens the JSONL request frame reader — the one
// function that runs directly on bytes an agent-controlled connection
// sends, before any policy or gateway logic ever sees them. readFrame's
// MaxLine bound (2MiB) must hold regardless of what garbage arrives,
// and this must never panic.
func FuzzReadRequest(f *testing.F) {
	seeds := []string{
		"",
		"\n",
		"{}\n",
		`{"task":"agt_x","secret":"s","id":1,"tool":"remote_exec","args":{}}` + "\n",
		`{"task":"` + string(make([]byte, 200)) + `"}` + "\n",
		"not json at all\n",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, data string) {
		r := bufio.NewReader(bytes.NewReader([]byte(data)))
		_, _ = ReadRequest(r)
		// No assertion beyond "does not panic" — ReadRequest's error
		// return already covers every rejection path; this fuzz target
		// exists to catch a panic (index out of range, nil deref) that
		// a unit test with hand-picked inputs wouldn't think to try.
	})
}
