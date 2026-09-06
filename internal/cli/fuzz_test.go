package cli

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"
)

// FuzzDecodeAdminBody hardens the admin API's request decoder against
// whatever bytes arrive on the loopback admin socket — bounded by the
// same 1MiB cap and strict-unknown-fields decoding every /grant,
// /revoke, and /pair handler relies on. Must never panic against any
// of GrantRequest, RevokeRequest, or PairRequest as the target shape.
func FuzzDecodeAdminBody(f *testing.F) {
	seeds := []string{
		"",
		"{}",
		`{"policy_yaml":"version: 1"}`,
		`{"task":"agt_x"}`,
		`{"task":"agt_x","ttl_override_ms":60000}`,
		"not json",
		`{"unknown_field":true}`,
		`{} {}`,
		"[]",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, body string) {
		for _, target := range []func() any{
			func() any { return &GrantRequest{} },
			func() any { return &RevokeRequest{} },
			func() any { return &PairRequest{} },
		} {
			v := target()
			rec := httptest.NewRecorder()
			req := httptest.NewRequestWithContext(context.Background(), "POST", "/admin", strings.NewReader(body))
			_ = decodeAdminBody(rec, req, v)
			// No assertion beyond "does not panic" — decodeAdminBody's
			// error return already covers every rejection path.
		}
	})
}
