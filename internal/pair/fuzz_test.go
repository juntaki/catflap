package pair

import "testing"

// FuzzDecode hardens the pairing-code parser: this is the one function
// that runs on completely untrusted input (whatever a human pastes into
// the MCP pair tool) before anything else in the pairing path executes.
// It must never panic, and a successfully decoded code must always
// re-encode to something that decodes back to the same transport+addr —
// Decode must not silently accept a shape Encode itself would never
// produce.
func FuzzDecode(f *testing.F) {
	seeds := []string{
		"",
		"CAT-",
		"CAT-AAAA",
		"CAT-@@@@",
		"not a pairing code",
	}
	if code, err := Encode("local", "127.0.0.1:12345"); err == nil {
		seeds = append(seeds, code)
	}
	if code, err := Encode("tailcat", "tcomFwWC1234567890abcdef"); err == nil {
		seeds = append(seeds, code)
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, code string) {
		transportName, addr, err := Decode(code)
		if err != nil {
			return
		}
		if transportName != "tailcat" && transportName != "local" {
			t.Fatalf("Decode(%q) returned an impossible transport %q", code, transportName)
		}
		if addr == "" {
			t.Fatalf("Decode(%q) returned ok with an empty address", code)
		}
		reEncoded, eerr := Encode(transportName, addr)
		if eerr != nil {
			t.Fatalf("Decode(%q) = (%q, %q), but Encode of that pair failed: %v", code, transportName, addr, eerr)
		}
		gotTransport, gotAddr, derr := Decode(reEncoded)
		if derr != nil {
			t.Fatalf("re-encoded code %q failed to decode: %v", reEncoded, derr)
		}
		if gotTransport != transportName || gotAddr != addr {
			t.Fatalf("decode->encode->decode not stable: got (%q,%q), want (%q,%q)", gotTransport, gotAddr, transportName, addr)
		}
	})
}
