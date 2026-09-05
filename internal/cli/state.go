package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/juntaki/catflap/internal/capability"
)

// StateFile is written by `serve` so `grant` can find the admin API.
// Per-task endpoints live in the capabilities themselves (1 task = 1 server).
type StateFile struct {
	Transport  string `json:"transport"`
	AdminAddr  string `json:"admin_addr"`
	AdminToken string `json:"admin_token"`
}

// DefaultStatePath returns ~/.catflap/serve.json (or $CATFLAP_STATE).
func DefaultStatePath() string {
	if v := os.Getenv("CATFLAP_STATE"); v != "" {
		return v
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "./.catflap-serve.json"
	}
	return home + "/.catflap/serve.json"
}

// DefaultAuditDir returns ~/.catflap/audit (or $CATFLAP_AUDIT).
func DefaultAuditDir() string {
	if v := os.Getenv("CATFLAP_AUDIT"); v != "" {
		return v
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "./audit"
	}
	return home + "/.catflap/audit"
}

func LoadState(path string) (*StateFile, error) {
	//nolint:gosec // reason: operator's --state path (or $CATFLAP_STATE); never agent input.
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read state %s: %w (is `serve` running?)", path, err)
	}
	var st StateFile
	if err := json.Unmarshal(raw, &st); err != nil {
		return nil, fmt.Errorf("parse state: %w", err)
	}
	return &st, nil
}

// GrantRequest asks the running server to mint a task.
type GrantRequest struct {
	PolicyYAML    string `json:"policy_yaml,omitempty"`
	TTLOverrideMs int64  `json:"ttl_override_ms,omitempty"`
}

// GrantResponse carries the minted capability.
type GrantResponse struct {
	Task       string `json:"task"`
	Capability string `json:"capability"`
	ExpiresAt  string `json:"expires_at"`
	Policy     string `json:"policy"`
}

// RevokeRequest asks the running server to destroy one task.
type RevokeRequest struct {
	Task string `json:"task"`
}

// RevokeResponse reports the outcome. Status is "revoked" or "unknown"
// (already gone); both are idempotent success.
type RevokeResponse struct {
	Task   string `json:"task"`
	Status string `json:"status"`
}

// PostGrant calls the admin API.
func PostGrant(adminAddr, token string, req GrantRequest) (*GrantResponse, error) {
	body, merr := json.Marshal(req)
	if merr != nil {
		return nil, fmt.Errorf("encode grant request: %w", merr)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	httpReq, err := http.NewRequestWithContext(ctx, "POST", "http://"+adminAddr+"/grant", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+token)
	res, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("grant request: %w", err)
	}
	defer func() { _ = res.Body.Close() }()
	raw, _ := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if res.StatusCode != 200 {
		return nil, fmt.Errorf("grant failed (%d): %s", res.StatusCode, string(raw))
	}
	var out GrantResponse
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("parse grant response: %w", err)
	}
	if _, err := capability.Decode(out.Capability); err != nil {
		return nil, fmt.Errorf("server returned invalid capability: %w", err)
	}
	return &out, nil
}

// PostRevoke calls the admin API to destroy one task. Unknown tasks are
// idempotent success (status "unknown"), not errors.
func PostRevoke(adminAddr, token, taskID string) (*RevokeResponse, error) {
	body, merr := json.Marshal(RevokeRequest{Task: taskID})
	if merr != nil {
		return nil, fmt.Errorf("encode revoke request: %w", merr)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	httpReq, err := http.NewRequestWithContext(ctx, "POST", "http://"+adminAddr+"/revoke", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+token)
	res, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("revoke request: %w", err)
	}
	defer func() { _ = res.Body.Close() }()
	raw, _ := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if res.StatusCode != 200 {
		return nil, fmt.Errorf("revoke failed (%d): %s", res.StatusCode, string(raw))
	}
	var out RevokeResponse
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("parse revoke response: %w", err)
	}
	return &out, nil
}
