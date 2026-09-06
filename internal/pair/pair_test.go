package pair

import "testing"

func TestEncodeDecodeRoundTrips(t *testing.T) {
	for _, tc := range []struct{ transportName, addr string }{
		{"local", "127.0.0.1:54321"},
		{"tailcat", "tcomFwWC1234567890abcdef"},
	} {
		code, err := Encode(tc.transportName, tc.addr)
		if err != nil {
			t.Fatalf("Encode(%q, %q): %v", tc.transportName, tc.addr, err)
		}
		if code[:len(CodePrefix)] != CodePrefix {
			t.Errorf("code %q missing prefix %q", code, CodePrefix)
		}
		gotTransport, gotAddr, err := Decode(code)
		if err != nil {
			t.Fatalf("Decode(%q): %v", code, err)
		}
		if gotTransport != tc.transportName || gotAddr != tc.addr {
			t.Errorf("Decode(%q) = (%q, %q), want (%q, %q)", code, gotTransport, gotAddr, tc.transportName, tc.addr)
		}
	}
}

func TestDecodeToleratesFormatting(t *testing.T) {
	code, err := Encode("local", "127.0.0.1:9")
	if err != nil {
		t.Fatal(err)
	}
	messy := " " + code + " "
	gotTransport, gotAddr, err := Decode(messy)
	if err != nil {
		t.Fatalf("Decode with surrounding whitespace: %v", err)
	}
	if gotTransport != "local" || gotAddr != "127.0.0.1:9" {
		t.Errorf("Decode(%q) = (%q, %q)", messy, gotTransport, gotAddr)
	}
}

func TestDecodeRejectsChecksumMismatch(t *testing.T) {
	code, err := Encode("local", "127.0.0.1:9")
	if err != nil {
		t.Fatal(err)
	}
	// Flip the last character so the CRC no longer matches.
	mangled := code[:len(code)-1] + flip(code[len(code)-1])
	if _, _, err := Decode(mangled); err == nil {
		t.Error("Decode must reject a code with a mismatched checksum")
	}
}

func flip(c byte) string {
	if c == 'A' {
		return "B"
	}
	return "A"
}

func TestDecodeRejectsGarbage(t *testing.T) {
	for _, bad := range []string{"", "not a code", "CAT-", "CAT-@@@@"} {
		if _, _, err := Decode(bad); err == nil {
			t.Errorf("Decode(%q) must fail", bad)
		}
	}
}
