package cli

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/juntaki/catflap/internal/pair"
)

// ResolveRendezvous returns the rendezvous URL in precedence order:
// explicit flag > $CATFLAP_RENDEZVOUS > config file > canonical default.
// Both share (publish) and mcp pair (fetch) resolve the same way, so the
// two ends rendezvous without further coordination.
//
// A config file error is never silently swallowed into "use the public
// default": an operator who configured a private rendezvous and then
// broke that config (bad permissions, malformed YAML, an explicit
// CATFLAP_CONFIG pointing nowhere) gets a clear error, not envelopes
// quietly published to pair.catflap.dev instead. Only the DEFAULT config
// path simply not existing (no config was ever set up) falls through.
func ResolveRendezvous(flagVal string) (string, error) {
	v, err := resolveRendezvous(flagVal)
	if err != nil {
		return "", err
	}
	if err := validateRendezvousURL(v); err != nil {
		return "", err
	}
	return v, nil
}

func resolveRendezvous(flagVal string) (string, error) {
	if v := strings.TrimSpace(flagVal); v != "" {
		return v, nil
	}
	if v := DefaultRendezvous(); v != "" {
		return v, nil
	}
	v, err := configRendezvous()
	if err != nil {
		return "", err
	}
	if v != "" {
		return v, nil
	}
	return pair.DefaultRendezvousURL, nil
}

// validateRendezvousURL requires https (except for loopback/localhost,
// for local development) and a plain base-URL shape: host required, no
// userinfo/query/fragment, and a path of "" or "/" only. pair.Fetch and
// pair.Publish build request URLs by string-concatenating a path onto
// this value (strings.TrimSuffix(rendezvousURL, "/") + "/v1/envelopes/…")
// rather than resolving it as a base via net/url, so any of those extra
// components would silently corrupt the request instead of erroring.
//
// The https requirement itself is availability, not confidentiality: the
// AEAD-sealed envelope's confidentiality doesn't depend on transport
// security — the wrap key travels out-of-band in the pairing code, never
// over this connection — but plaintext HTTP still lets a network
// attacker deny availability (drop or corrupt publish/fetch, or burn a
// pairing code before its intended recipient fetches it) for free.
func validateRendezvousURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("bad rendezvous URL %q: %w", raw, err)
	}
	if u.Opaque != "" {
		return fmt.Errorf("rendezvous URL %q must not be opaque (missing //?)", raw)
	}
	if u.Host == "" {
		return fmt.Errorf("rendezvous URL %q must include a host", raw)
	}
	if u.User != nil {
		return fmt.Errorf("rendezvous URL %q must not contain userinfo", raw)
	}
	if u.RawQuery != "" {
		return fmt.Errorf("rendezvous URL %q must not contain a query string", raw)
	}
	if u.Fragment != "" {
		return fmt.Errorf("rendezvous URL %q must not contain a fragment", raw)
	}
	if u.Path != "" && u.Path != "/" {
		return fmt.Errorf("rendezvous URL %q must not contain a path", raw)
	}
	if u.Scheme == "https" {
		return nil
	}
	host := u.Hostname()
	if u.Scheme == "http" && (host == "localhost" || strings.HasSuffix(host, ".localhost") || host == "127.0.0.1" || host == "::1") {
		return nil
	}
	return fmt.Errorf("rendezvous URL %q must use https (http allowed only for localhost/127.0.0.1)", raw)
}

// DefaultRendezvous returns the configured rendezvous URL, if any.
func DefaultRendezvous() string {
	return strings.TrimSpace(os.Getenv("CATFLAP_RENDEZVOUS"))
}

// configRendezvous reads rendezvous_url from the operator config file. A
// missing DEFAULT path (no CATFLAP_CONFIG override) means no value, so
// callers fall further down the chain; anything else that goes wrong —
// an explicit path that can't be read, or a file that exists but won't
// parse — is a real error, not a silent fallback.
func configRendezvous() (string, error) {
	explicit := strings.TrimSpace(os.Getenv("CATFLAP_CONFIG"))
	path := explicit
	if path == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			// No CATFLAP_CONFIG override and no resolvable home dir: there
			// is no default config path to even check, which is the same
			// as "no config file" — fall through, don't error.
			//nolint:nilerr // reason: deliberate — see comment above.
			return "", nil
		}
		path = filepath.Join(home, ".config", "catflap", "config.yaml")
	}
	//nolint:gosec // reason: path is either the operator's explicit CATFLAP_CONFIG or a fixed per-user dir; never agent input.
	raw, err := os.ReadFile(path)
	if err != nil {
		if explicit == "" && os.IsNotExist(err) {
			return "", nil
		}
		return "", fmt.Errorf("read rendezvous config %s: %w", path, err)
	}
	var cfg struct {
		RendezvousURL string `yaml:"rendezvous_url"`
	}
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)
	if err := dec.Decode(&cfg); err != nil {
		return "", fmt.Errorf("parse rendezvous config %s: %w", path, err)
	}
	// Strict parsing must also reject a second YAML document: otherwise
	// "unknown fields fail closed" only holds for the first one.
	var extra any
	switch derr := dec.Decode(&extra); {
	case derr == nil:
		return "", fmt.Errorf("parse rendezvous config %s: unexpected second document", path)
	case errors.Is(derr, io.EOF):
		// only document present, as expected
	default:
		return "", fmt.Errorf("parse rendezvous config %s: %w", path, derr)
	}
	return cfg.RendezvousURL, nil
}
