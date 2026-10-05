package auth

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	internalconfig "github.com/router-for-me/CLIProxyAPI/v8/internal/config"
)

// The first promotion of a pool identity requires the operator to present the
// exact runtime credential digest. PoolPendingIdentities must expose loaded
// codex OAuth identities (and their digests) so the bootstrap is achievable,
// and must hide them once the identity is trusted on the same digest.
func TestPoolPendingIdentitiesExposeBootstrapDigests(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "auths")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(root, "grants.json")
	checkpoint := filepath.Join(root, "checkpoint.jsonl")
	t.Setenv("CLEARAPI_POOL_ROLE", "service")
	t.Setenv("CLEARAPI_POOL_ADMISSION_FILE", file)
	t.Setenv("CLEARAPI_POOL_EXECUTOR_ID", "synthetic-executor")
	t.Setenv("CLEARAPI_POOL_CHECKPOINT_FILE", checkpoint)
	if err := ProvisionPoolCheckpoint(checkpoint, "synthetic-executor"); err != nil {
		t.Fatal(err)
	}

	m := NewManager(nil, nil, nil)
	m.SetConfig(&internalconfig.Config{AuthDir: dir})

	auth := &Auth{ID: "synthetic-pool-account", Provider: "codex", FileName: "synthetic-pool-account.json", Status: StatusActive, Attributes: map[string]string{AttributeAuthKind: AuthKindOAuth}, Metadata: map[string]any{"access_token": "synthetic-unused", "account_id": "synthetic-account-id"}}
	if _, err := m.Register(context.Background(), auth); err != nil {
		t.Fatal(err)
	}
	record := PoolGrantFile{GuardVersion: PoolGuardVersion, Revision: 1, ExecutorID: "synthetic-executor", Grants: []PoolGrant{{AuthID: auth.ID, Provider: auth.Provider, CredentialDigest: PoolCredentialDigest(auth), Models: []string{"synthetic-native"}, Capabilities: []string{"text_chat", "stream_text", "exact_usage"}, Enabled: true, MaxConcurrency: 1, ExpiresAt: time.Now().Add(10 * time.Minute).Unix(), SourceEvidence: []string{"synthetic-source"}, TestEvidence: []string{"synthetic-test"}}}}
	writePoolGrant(t, file, record)

	pending, err := m.PoolPendingIdentities()
	if err != nil {
		t.Fatalf("PoolPendingIdentities: %v", err)
	}
	if len(pending) != 1 || pending[0].AuthID != auth.ID || len(pending[0].CredentialDigest) != 64 {
		t.Fatalf("pending identities = %+v, want the loaded identity with its digest", pending)
	}
	if pending[0].CredentialDigest != PoolCredentialDigest(auth) {
		t.Fatal("bootstrap digest does not match the runtime credential digest")
	}

	if err := m.PromotePoolIdentities(context.Background(), PoolPromotion{ExpectedRevision: 1, Identities: pending}); err != nil {
		t.Fatalf("promotion with bootstrap digest rejected: %v", err)
	}

	pending, err = m.PoolPendingIdentities()
	if err != nil {
		t.Fatalf("PoolPendingIdentities after promotion: %v", err)
	}
	if len(pending) != 0 {
		t.Fatalf("pending after promotion = %d, want 0", len(pending))
	}
}
