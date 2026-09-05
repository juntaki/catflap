package cli

import (
	"os"
	"path/filepath"
	"testing"
)

// TestConfigRendezvousFailsClosedOnMalformed covers the P1 fix: a config
// file error must never be swallowed into "use the public default" — an
// operator who configured a private rendezvous and then broke that
// config (bad YAML here) must see an error, not have envelopes silently
// published to pair.catflap.dev instead.
func TestConfigRendezvousFailsClosedOnMalformed(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte("rendezvous_url: [not a string\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CATFLAP_CONFIG", path)
	t.Setenv("CATFLAP_RENDEZVOUS", "")

	if _, err := ResolveRendezvous(""); err == nil {
		t.Error("malformed config file must error, not fall back silently")
	}
}

// TestConfigRendezvousFailsClosedOnExplicitMissing covers the same fix
// for an explicit CATFLAP_CONFIG pointing nowhere: unlike the default
// path simply not existing (no config was ever set up), an operator who
// explicitly named a config file gets an error when it can't be read.
func TestConfigRendezvousFailsClosedOnExplicitMissing(t *testing.T) {
	t.Setenv("CATFLAP_CONFIG", filepath.Join(t.TempDir(), "nonexistent.yaml"))
	t.Setenv("CATFLAP_RENDEZVOUS", "")

	if _, err := ResolveRendezvous(""); err == nil {
		t.Error("explicit CATFLAP_CONFIG that can't be read must error")
	}
}

// TestRendezvousURLRequiresHTTPS covers the P2 fix: a rendezvous URL
// must be https, with an explicit carve-out for local development
// (localhost/127.0.0.1/::1 over plain http). Plaintext HTTP to a real
// remote endpoint doesn't leak the sealed capability (the AEAD wrap key
// travels out-of-band in the pairing code), but it does let a network
// attacker deny availability — drop or corrupt publish/fetch, or burn a
// pairing code before its intended recipient — without breaking any
// crypto at all.
func TestRendezvousURLRequiresHTTPS(t *testing.T) {
	t.Setenv("CATFLAP_CONFIG", "")
	t.Setenv("CATFLAP_RENDEZVOUS", "")
	if _, err := ResolveRendezvous("http://pair.example.com"); err == nil {
		t.Error("plain http to a non-local host must be rejected")
	}
	if v, err := ResolveRendezvous("https://pair.example.com"); err != nil || v != "https://pair.example.com" {
		t.Errorf("https must be accepted: %v %q", err, v)
	}
	for _, local := range []string{"http://127.0.0.1:8471", "http://localhost:8471", "http://[::1]:8471"} {
		if v, err := ResolveRendezvous(local); err != nil || v != local {
			t.Errorf("plain http to %q (local dev) must be accepted: %v", local, err)
		}
	}
}

// TestConfigRendezvousRejectsTrailingDocument covers strict-parser parity
// with the policy YAML parser: a second `---`-separated document must be
// rejected, not silently ignored.
func TestConfigRendezvousRejectsTrailingDocument(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte("rendezvous_url: https://ok.example\n---\nwhatever: ignored\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CATFLAP_CONFIG", path)
	t.Setenv("CATFLAP_RENDEZVOUS", "")

	if _, err := ResolveRendezvous(""); err == nil {
		t.Error("a second YAML document in the config file must be rejected")
	}
}

// TestRendezvousURLRejectsUnsafeShapes covers the P2 fix: Fetch/Publish
// build request URLs by string-concatenating a path onto the resolved
// rendezvous URL rather than resolving it as a base via net/url, so a
// query string, fragment, userinfo, missing host, or extra path
// component would silently corrupt every request instead of erroring
// up front at configuration time.
func TestRendezvousURLRejectsUnsafeShapes(t *testing.T) {
	t.Setenv("CATFLAP_CONFIG", "")
	t.Setenv("CATFLAP_RENDEZVOUS", "")
	bad := []string{
		"https:opaque",                        // no host, opaque
		"https://",                            // no host
		"https://user:pass@pair.example.com",  // userinfo
		"https://pair.example.com?x=1",        // query
		"https://pair.example.com#frag",       // fragment
		"https://pair.example.com/extra/path", // path
	}
	for _, raw := range bad {
		if _, err := ResolveRendezvous(raw); err == nil {
			t.Errorf("ResolveRendezvous(%q) must be rejected", raw)
		}
	}
	good := []string{"https://pair.example.com", "https://pair.example.com/"}
	for _, raw := range good {
		if _, err := ResolveRendezvous(raw); err != nil {
			t.Errorf("ResolveRendezvous(%q) must be accepted: %v", raw, err)
		}
	}
}

func TestConfigRendezvousPrecedence(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte("rendezvous_url: https://from-config.example\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CATFLAP_CONFIG", path)
	t.Setenv("CATFLAP_RENDEZVOUS", "https://from-env.example")

	// Explicit flag wins over everything.
	if v, err := ResolveRendezvous("https://from-flag.example"); err != nil || v != "https://from-flag.example" {
		t.Errorf("flag must win: %v %q", err, v)
	}
	// Env wins over config file.
	if v, err := ResolveRendezvous(""); err != nil || v != "https://from-env.example" {
		t.Errorf("env must win over config: %v %q", err, v)
	}
	t.Setenv("CATFLAP_RENDEZVOUS", "")
	// Config file wins over the canonical default.
	if v, err := ResolveRendezvous(""); err != nil || v != "https://from-config.example" {
		t.Errorf("config file must win over default: %v %q", err, v)
	}
}
