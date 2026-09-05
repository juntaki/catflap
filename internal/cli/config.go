package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"

	"github.com/juntaki/catflap/internal/pair"
	"gopkg.in/yaml.v3"
)

// ResolveRendezvous returns the rendezvous URL in precedence order:
// explicit flag > $CATFLAP_RENDEZVOUS > config file > canonical default.
// Both share (publish) and mcp pair (fetch) resolve the same way, so the
// two ends rendezvous without further coordination.
func ResolveRendezvous(flagVal string) string {
	if v := strings.TrimSpace(flagVal); v != "" {
		return v
	}
	if v := DefaultRendezvous(); v != "" {
		return v
	}
	if v := strings.TrimSpace(configRendezvous()); v != "" {
		return v
	}
	return pair.DefaultRendezvousURL
}

// DefaultRendezvous returns the configured rendezvous URL, if any.
func DefaultRendezvous() string {
	return strings.TrimSpace(os.Getenv("CATFLAP_RENDEZVOUS"))
}

// configRendezvous reads rendezvous_url from the operator config file.
// Absent or broken config means no value (never an error): pairing falls
// back down the chain.
func configRendezvous() string {
	path := strings.TrimSpace(os.Getenv("CATFLAP_CONFIG"))
	if path == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return ""
		}
		path = filepath.Join(home, ".config", "catflap", "config.yaml")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	var cfg struct {
		RendezvousURL string `yaml:"rendezvous_url"`
	}
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)
	if err := dec.Decode(&cfg); err != nil {
		return ""
	}
	return cfg.RendezvousURL
}
