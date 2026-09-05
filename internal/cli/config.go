package cli

import (
	"bytes"
	"fmt"
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
	return cfg.RendezvousURL, nil
}
