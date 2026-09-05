package capability

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// Prefix is the human-recognizable capability token prefix.
const Prefix = "agc1_"

// Capability is the bearer token handed to one agent task.
// It embeds everything the agent-side adapter needs to dial back:
// the Tailcat address (reachability), the ephemeral client identity,
// and the task auth secret. The server is the source of truth for
// expiry; the embedded ExpiresAt is a client-side hint for fast failure.
type Capability struct {
	Version    int       `json:"v"`
	TaskID     string    `json:"task"`
	Transport  string    `json:"transport"` // "tailcat" or "local"
	Endpoint   string    `json:"endpoint"`  // tailcat addr, or host:port for local
	ClientPriv string    `json:"client_priv,omitempty"`
	TaskSecret string    `json:"task_secret"`
	ExpiresAt  time.Time `json:"expires_at"`
	Policy     string    `json:"policy"`
	PolicyHash string    `json:"policy_hash,omitempty"` // short prefix of the policy CanonicalHash
	// Tools lists the MCP tools this task exposes (policy-normalized).
	// The field is always present on new capabilities (possibly empty);
	// only absent (nil) on legacy capabilities, which imply
	// exec/read/stat and never write.
	Tools []string `json:"tools"`
	// MaxExecMs carries the task's max exec duration so the agent adapter
	// waits at least as long as the longest permitted operation (plus
	// margin), instead of timing out early while the operation continues.
	MaxExecMs int64 `json:"max_exec_ms,omitempty"`
}

// NewTaskID returns a task id like "agt_01K..." (random, unique).
func NewTaskID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return "agt_" + hex.EncodeToString(b[:])[:16]
}

// NewSecret returns a random task auth secret.
func NewSecret() string {
	var b [24]byte
	_, _ = rand.Read(b[:])
	return base64.RawURLEncoding.EncodeToString(b[:])
}

// Encode serializes the capability to its bearer string form.
// The payload is versioned strings/time only and cannot fail to marshal;
// callers treat "" as unusable (Decode rejects it).
func (c *Capability) Encode() string {
	raw, err := json.Marshal(c)
	if err != nil {
		return ""
	}
	return Prefix + base64.RawURLEncoding.EncodeToString(raw)
}

// Decode parses a bearer string back into a Capability. Every capability
// this process mints is v1 (see server-side Encode callers); v0/unversioned
// tokens are a legacy shape from before versioning existed and get only
// the original, looser checks. Pairing turns Decode into a real protocol
// boundary (untrusted encrypted envelope in, Capability out), so v1
// tokens get strict field validation instead of just the three fields
// that happened to matter for internally-generated tokens.
func Decode(s string) (*Capability, error) {
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(s, Prefix) {
		return nil, fmt.Errorf("capability must start with %q", Prefix)
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(s, Prefix))
	if err != nil {
		return nil, fmt.Errorf("invalid capability encoding: %w", err)
	}
	var c Capability
	if err := json.Unmarshal(raw, &c); err != nil {
		return nil, fmt.Errorf("invalid capability payload: %w", err)
	}
	if c.TaskID == "" || c.Endpoint == "" || c.TaskSecret == "" {
		return nil, fmt.Errorf("capability missing required fields")
	}
	if c.Version == 0 {
		if c.Transport == "" {
			c.Transport = "tailcat"
		}
		return &c, nil
	}
	if err := c.validateV1(); err != nil {
		return nil, err
	}
	return &c, nil
}

// validateV1 enforces the v1 shape strictly: unlike the legacy default-
// filling above, an invalid v1 token is rejected rather than patched up.
func (c *Capability) validateV1() error {
	if c.Version != 1 {
		return fmt.Errorf("unsupported capability version %d", c.Version)
	}
	switch c.Transport {
	case "tailcat":
		if c.ClientPriv == "" {
			return fmt.Errorf("tailcat capability missing client_priv")
		}
	case "local":
		// local dials a bare host:port; no client identity to embed.
	default:
		return fmt.Errorf("unknown capability transport %q", c.Transport)
	}
	if c.ExpiresAt.IsZero() {
		return fmt.Errorf("v1 capability missing expires_at")
	}
	return nil
}

// Expired reports whether the capability hint says expired.
func (c *Capability) Expired(now time.Time) bool {
	return !c.ExpiresAt.IsZero() && now.After(c.ExpiresAt)
}
