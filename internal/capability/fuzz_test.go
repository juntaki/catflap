package capability

import (
	"testing"
	"time"
)

// FuzzDecode hardens the capability bearer-string parser. This runs on
// input that, before the pairing rewrite, came from a semi-trusted HTTP
// rendezvous and, even now (the legacy --cap/--cap-file flow, and a
// pair server's own delivery), is a real protocol boundary: whatever
// bytes arrive, Decode must never panic, and anything it accepts must
// re-encode to something that decodes back to an equivalent capability
// (decode->encode->decode stability).
func FuzzDecode(f *testing.F) {
	seeds := []string{
		"",
		Prefix,
		Prefix + "not-base64!!!",
		"not-even-prefixed",
	}
	valid := &Capability{
		Version: 1, TaskID: "agt_x", Name: "n",
		Transport: "local", Endpoint: "127.0.0.1:1", TaskSecret: "s",
		ExpiresAt: time.Now().Add(time.Hour),
	}
	if enc := valid.Encode(); enc != "" {
		seeds = append(seeds, enc)
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		cp, err := Decode(s)
		if err != nil {
			return
		}
		if cp.TaskID == "" || cp.Endpoint == "" || cp.TaskSecret == "" {
			t.Fatalf("Decode(%q) succeeded but left a required field empty: %+v", s, cp)
		}
		reEncoded := cp.Encode()
		if reEncoded == "" {
			t.Fatalf("Decode(%q) = %+v, but re-Encode failed", s, cp)
		}
		got, derr := Decode(reEncoded)
		if derr != nil {
			t.Fatalf("re-encoded capability failed to decode: %v (from %+v)", derr, cp)
		}
		if got.TaskID != cp.TaskID || got.TaskSecret != cp.TaskSecret || got.Endpoint != cp.Endpoint {
			t.Fatalf("decode->encode->decode not stable: got %+v, want %+v", got, cp)
		}
	})
}
