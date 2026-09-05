package capability

import (
	"crypto/rand"
	"crypto/sha256"
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
	PolicyHash string    `json:"policy_hash,omitempty"`
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

// PolicyHashOf returns a short hash identifying a policy snapshot.
func PolicyHashOf(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])[:12]
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

// Decode parses a bearer string back into a Capability.
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
	if c.Transport == "" {
		c.Transport = "tailcat"
	}
	return &c, nil
}

// Expired reports whether the capability hint says expired.
func (c *Capability) Expired(now time.Time) bool {
	return !c.ExpiresAt.IsZero() && now.After(c.ExpiresAt)
}
