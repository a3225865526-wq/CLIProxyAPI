package executor

import (
	"testing"

	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
)

// File-based auth records persist their fields as metadata. codexCreds must
// honor the operator-provisioned base_url metadata the same way it honors the
// access_token fallback, so a staging credential can target a private
// upstream without any attribute plumbing.
func TestCodexCredsBaseURLMetadataFallback(t *testing.T) {
	auth := &coreauth.Auth{
		Provider: "codex",
		Metadata: map[string]any{
			"access_token": "staging-token",
			"base_url":     "http://mock-upstream:8080/backend-api/codex",
		},
	}
	apiKey, baseURL := codexCreds(auth)
	if apiKey != "staging-token" {
		t.Fatalf("apiKey = %q, want staged access_token", apiKey)
	}
	if baseURL != "http://mock-upstream:8080/backend-api/codex" {
		t.Fatalf("baseURL = %q, want metadata override", baseURL)
	}

	// An explicit attribute still wins over metadata.
	auth.Attributes = map[string]string{"base_url": "http://attribute-wins:1/backend-api/codex"}
	if _, baseURL = codexCreds(auth); baseURL != "http://attribute-wins:1/backend-api/codex" {
		t.Fatalf("baseURL = %q, want attribute precedence", baseURL)
	}
}
