package auth

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
)

// PG-29 canonical credential identity tests. The v1 digest hashed the auth ID,
// file name, every Attribute and every Metadata entry, so the filestore startup
// loader and the watcher synthesizer derived different digests for the same
// credential: promote bound the watcher digest, the restart used the filestore
// digest, trust failed and the account quarantined. The v2 canonical identity
// hashes an explicit whitelist (provider, kind, stable account subject) with
// deterministic serialization, so every pipeline derives the same digest.

// rawCodexCredential returns the raw metadata shared by every loader pipeline.
func rawCodexCredential(accountID string) map[string]any {
	return map[string]any{
		"type":          "codex",
		"access_token":  "staging-access-token",
		"refresh_token": "staging-refresh-token",
		"id_token":      "staging-not-a-jwt",
		"account_id":    accountID,
		"email":         "operator@staging.invalid",
		"expired":       "2099-01-01T00:00:00Z",
		"last_refresh":  "2026-10-05T00:00:00Z",
		"plan_type":     "pro",
		"base_url":      "http://mock-a:8080/backend-api/codex",
	}
}

// filestoreStyleCodexAuth builds the Auth exactly the way the sdk/auth
// FileTokenStore startup loader does for a non-plugin codex file.
func filestoreStyleCodexAuth(baseDir, name, accountID string) *Auth {
	raw := rawCodexCredential(accountID)
	path := filepath.Join(baseDir, name)
	auth := &Auth{
		ID:       name,
		Provider: "codex",
		FileName: name,
		Label:    "operator@staging.invalid",
		Status:   StatusActive,
		Attributes: map[string]string{
			AttributePath:          path,
			AttributeSource:        path,
			AttributeSourceBackend: AuthSourceFile,
			"email":                "operator@staging.invalid",
		},
		Metadata: raw,
	}
	return auth
}

// watcherStyleCodexAuth builds the Auth exactly the way the watcher
// synthesizer does for the same file (plan_type/auth_kind attributes, no email
// attribute, base-name FileName).
func watcherStyleCodexAuth(baseDir, name, accountID string) *Auth {
	raw := rawCodexCredential(accountID)
	path := filepath.Join(baseDir, name)
	auth := &Auth{
		ID:       name,
		Provider: "codex",
		FileName: name,
		Label:    "operator@staging.invalid",
		Status:   StatusActive,
		Attributes: map[string]string{
			AttributeSource:        path,
			AttributePath:          path,
			AttributeSourceBackend: AuthSourceFile,
			"auth_kind":            AuthKindOAuth,
			"plan_type":            "pro",
			"excluded_models_hash": "synthetic-hash",
		},
		Metadata: raw,
	}
	return auth
}

// filestoreStyleStore is a Store that loads auth files with filestore
// semantics, used to exercise the restart path without importing sdk/auth
// (which would create an import cycle with this package).
type filestoreStyleStore struct {
	dir string
}

func (store *filestoreStyleStore) List(context.Context) ([]*Auth, error) {
	entries, err := os.ReadDir(store.dir)
	if err != nil {
		return nil, err
	}
	items := make([]*Auth, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(strings.ToLower(entry.Name()), ".json") {
			continue
		}
		path := filepath.Join(store.dir, entry.Name())
		data, errRead := os.ReadFile(path)
		if errRead != nil || len(data) == 0 {
			continue
		}
		metadata := make(map[string]any)
		if errUnmarshal := json.Unmarshal(data, &metadata); errUnmarshal != nil {
			continue
		}
		NormalizeCredentialMetadata(metadata)
		if provider, _ := metadata["type"].(string); !strings.EqualFold(strings.TrimSpace(provider), "codex") {
			continue
		}
		// The fixture journal binds AuthID without the .json suffix; the real
		// filestore derives the ID from the relative path, so mirror a store
		// whose IDs are the file stem to keep the restart comparison exact.
		auth := &Auth{
			ID:       strings.TrimSuffix(entry.Name(), ".json"),
			Provider: "codex",
			FileName: entry.Name(),
			Status:   StatusActive,
			Attributes: map[string]string{
				AttributePath:          path,
				AttributeSource:        path,
				AttributeSourceBackend: AuthSourceFile,
			},
			Metadata: metadata,
		}
		if email, ok := metadata["email"].(string); ok && email != "" {
			auth.Attributes["email"] = email
		}
		items = append(items, auth)
	}
	return items, nil
}

func (store *filestoreStyleStore) Save(_ context.Context, auth *Auth) (string, error) {
	path := ""
	if auth.Attributes != nil {
		path = auth.Attributes[AttributePath]
	}
	if path == "" {
		path = filepath.Join(store.dir, auth.ID)
	}
	raw := auth.Metadata
	if raw == nil {
		raw = map[string]any{}
	}
	data, err := json.Marshal(raw)
	if err != nil {
		return "", err
	}
	return path, os.WriteFile(path, data, 0o600)
}

func (store *filestoreStyleStore) Delete(_ context.Context, id string) error {
	return os.Remove(filepath.Join(store.dir, id))
}

func v1StyleDigest(seed string) string {
	sum := sha256.Sum256([]byte(seed))
	return hex.EncodeToString(sum[:])
}

// TestPoolCredentialIdentityPipelinesConverge covers the whitelist invariants:
// loader pipeline, mount path, runtime enrichment, repetition, and map
// insertion order must never move the canonical digest.
func TestPoolCredentialIdentityPipelinesConverge(t *testing.T) {
	root := t.TempDir()
	name := "stage7-pool-a.json"

	t.Run("filestore-vs-watcher-same-credential-same-digest", func(t *testing.T) {
		filestore := filestoreStyleCodexAuth(root, name, "stage7-account-a")
		watcher := watcherStyleCodexAuth(root, name, "stage7-account-a")
		digest := PoolCredentialDigest(filestore)
		if digest == "" || digest != PoolCredentialDigest(watcher) {
			t.Fatalf("pipeline digests diverge: filestore=%s watcher=%s", digest, PoolCredentialDigest(watcher))
		}
	})

	t.Run("different-absolute-path-same-digest", func(t *testing.T) {
		digest := PoolCredentialDigest(filestoreStyleCodexAuth(root, name, "stage7-account-a"))
		for _, dir := range []string{"/data/auths", "/app/auths", "/tmp/auths", t.TempDir()} {
			moved := filestoreStyleCodexAuth(dir, name, "stage7-account-a")
			if PoolCredentialDigest(moved) != digest {
				t.Fatalf("path %q changed the canonical identity", dir)
			}
			watcherMoved := watcherStyleCodexAuth(dir, name, "stage7-account-a")
			if PoolCredentialDigest(watcherMoved) != digest {
				t.Fatalf("watcher path %q changed the canonical identity", dir)
			}
		}
	})

	t.Run("runtime-enrichment-does-not-change-digest", func(t *testing.T) {
		base := watcherStyleCodexAuth(root, name, "stage7-account-a")
		digest := PoolCredentialDigest(base)
		enriched := base.Clone()
		enriched.Attributes["auth_kind"] = AuthKindOAuth
		enriched.Attributes["plan_type"] = "team"
		enriched.Attributes["source_backend"] = AuthSourceFile
		enriched.Attributes["derived_source"] = "synthetic"
		enriched.Attributes["health"] = "degraded"
		enriched.Attributes["excluded_models"] = "model-a,model-b"
		enriched.Metadata["ui_label"] = "billing account"
		enriched.Metadata["health_metadata"] = "degraded"
		if PoolCredentialDigest(enriched) != digest {
			t.Fatal("runtime enrichment changed the canonical identity")
		}
	})

	t.Run("deterministic-repeated-digest", func(t *testing.T) {
		auth := filestoreStyleCodexAuth(root, name, "stage7-account-a")
		first := PoolCredentialDigest(auth)
		for i := 0; i < 8; i++ {
			if again := PoolCredentialDigest(auth.Clone()); again != first {
				t.Fatalf("digest not deterministic: %s vs %s", again, first)
			}
		}
	})

	t.Run("map-insertion-order-irrelevant", func(t *testing.T) {
		one := filestoreStyleCodexAuth(root, name, "stage7-account-a")
		two := filestoreStyleCodexAuth(root, name, "stage7-account-a")
		one.Metadata["alpha"] = "1"
		one.Metadata["beta"] = "2"
		one.Attributes["alpha"] = "1"
		one.Attributes["beta"] = "2"
		two.Metadata["beta"] = "2"
		two.Metadata["alpha"] = "1"
		two.Attributes["beta"] = "2"
		two.Attributes["alpha"] = "1"
		if PoolCredentialDigest(one) != PoolCredentialDigest(two) {
			t.Fatal("map insertion order changed the canonical identity")
		}
	})
}

// TestPoolCredentialIdentityOAuthRefreshStable pins the refresh semantics: a
// normal access-token refresh rewrites rotating material only and must never
// move the canonical identity, even when the refresh token rotates or the
// email claim disappears.
func TestPoolCredentialIdentityOAuthRefreshStable(t *testing.T) {
	root := t.TempDir()
	before := PoolCredentialDigest(watcherStyleCodexAuth(root, "stage7-pool-a.json", "stage7-account-a"))
	if before == "" {
		t.Fatal("fixture identity missing")
	}
	refreshed := watcherStyleCodexAuth(root, "stage7-pool-a.json", "stage7-account-a")
	refreshed.Metadata["access_token"] = "staging-access-token-rotated"
	refreshed.Metadata["refresh_token"] = "staging-refresh-token-rotated"
	refreshed.Metadata["id_token"] = "staging-not-a-jwt-refreshed"
	refreshed.Metadata["expired"] = "2099-06-01T00:00:00Z"
	refreshed.Metadata["last_refresh"] = "2026-10-05T12:00:00Z"
	refreshed.Metadata["plan_type"] = "team"
	refreshed.Metadata["email"] = ""
	if after := PoolCredentialDigest(refreshed); after != before {
		t.Fatalf("normal token refresh changed the canonical identity: %s -> %s", before, after)
	}
	filestoreBefore := PoolCredentialDigest(filestoreStyleCodexAuth(root, "stage7-pool-a.json", "stage7-account-a"))
	if filestoreBefore != before {
		t.Fatal("pipeline digests diverged across refresh")
	}
}

// TestPoolCredentialIdentityReplacementDetected pins the replacement
// semantics: a different provider account, or a rotated API key, must change
// the identity; credentials without stable material fail closed.
func TestPoolCredentialIdentityReplacementDetected(t *testing.T) {
	root := t.TempDir()
	name := "stage7-pool-a.json"
	original := PoolCredentialDigest(filestoreStyleCodexAuth(root, name, "stage7-account-a"))
	replaced := PoolCredentialDigest(filestoreStyleCodexAuth(root, name, "stage7-account-b"))
	if replaced == "" || replaced == original {
		t.Fatal("credential replacement kept the canonical identity")
	}
	// Same file name and auth ID, different credential bytes for another account.
	if digest := PoolCredentialDigest(watcherStyleCodexAuth(root, name, "stage7-account-b")); digest != replaced {
		t.Fatal("pipelines disagree about the replacement identity")
	}
	// API key rotation changes the identity.
	key := func(secret string) *Auth {
		return &Auth{ID: "key-1", Provider: "codex", Status: StatusActive, Attributes: map[string]string{AttributeAPIKey: secret, AttributeAuthKind: AuthKindAPIKey}}
	}
	keyDigest := PoolCredentialDigest(key("sk-synthetic-original"))
	if keyDigest == "" || PoolCredentialDigest(key("sk-synthetic-rotated")) == keyDigest {
		t.Fatal("api key rotation did not change the identity")
	}
	// A credential with no stable identity material admits nothing (fail closed).
	hollow := &Auth{ID: "hollow", Provider: "codex", Status: StatusActive, Attributes: map[string]string{AttributeAuthKind: AuthKindOAuth}, Metadata: map[string]any{"access_token": "synthetic"}}
	if digest := PoolCredentialDigest(hollow); digest != "" {
		t.Fatalf("credential without stable identity material produced digest %s", digest)
	}
}

// TestPoolIdentityPromoteRestartTrusted is the PG-29 deployment regression:
// promote binds the canonical digest of the watcher-built runtime auth, and a
// restart that loads the same credential through filestore semantics must keep
// the identity, the trust, the capability, and the active auth.
func TestPoolIdentityPromoteRestartTrusted(t *testing.T) {
	m, executor, _, _, _ := poolGuardFixture(t, "service")
	dir := m.runtimeConfigSnapshot().AuthDir
	if err := os.WriteFile(filepath.Join(dir, "synthetic-pool-account.json"), mustJSON(t, rawCodexCredential("synthetic-account-id")), 0o600); err != nil {
		t.Fatal(err)
	}
	revision, trustStates, err := m.PoolTrustSnapshot()
	if err != nil || len(trustStates) != 1 || trustStates[0].State != PoolTrustTrusted || trustStates[0].IdentityVersion != CredentialSecurityIdentityVersion {
		t.Fatalf("fixture trust = %+v err=%v", trustStates, err)
	}
	if err := poolRequest(m); err != nil || executor.calls.Load() != 1 {
		t.Fatalf("pre-restart admission failed: %v", err)
	}

	// Restart: fresh manager, filestore-style store, same policy and journal.
	restarted := NewManager(&filestoreStyleStore{dir: dir}, nil, nil)
	restarted.SetConfig(m.runtimeConfigSnapshot())
	restarted.RegisterExecutor(executor)
	if err := restarted.Load(context.Background()); err != nil {
		t.Fatalf("restart load failed: %v", err)
	}
	loaded, ok := restarted.GetByID("synthetic-pool-account")
	if !ok || loaded.Disabled || loaded.Status != StatusActive {
		t.Fatalf("restart quarantined the account: %+v", loaded)
	}
	revision2, trustStates2, err := restarted.PoolTrustSnapshot()
	if err != nil || revision2 != revision || len(trustStates2) != 1 || trustStates2[0].State != PoolTrustTrusted || trustStates2[0].CredentialDigest != PoolCredentialDigest(loaded) {
		t.Fatalf("trust did not survive the restart: rev=%d states=%+v err=%v", revision2, trustStates2, err)
	}
	if PoolCredentialDigest(loaded) != trustStates2[0].CredentialDigest {
		t.Fatal("restart identity mismatch")
	}
	if pending, errPending := restarted.PoolPendingIdentities(); errPending != nil || len(pending) != 0 {
		t.Fatalf("trusted identity listed as pending after restart: %+v err=%v", pending, errPending)
	}
	if err := poolRequest(restarted); err != nil || executor.calls.Load() != 2 {
		t.Fatalf("post-restart admission failed: %v", err)
	}
}

// TestPoolIdentityCapabilityAndRevocationRestart pins STEP 1B/3 restart
// semantics on top of the canonical identity.
func TestPoolIdentityCapabilityAndRevocationRestart(t *testing.T) {
	t.Run("capability-still-valid", func(t *testing.T) {
		m, executor, _, _, _ := poolGuardFixture(t, "service")
		dir := m.runtimeConfigSnapshot().AuthDir
		if err := os.WriteFile(filepath.Join(dir, "synthetic-pool-account.json"), mustJSON(t, rawCodexCredential("synthetic-account-id")), 0o600); err != nil {
			t.Fatal(err)
		}
		restarted := NewManager(&filestoreStyleStore{dir: dir}, nil, nil)
		restarted.SetConfig(m.runtimeConfigSnapshot())
		restarted.RegisterExecutor(executor)
		if err := restarted.Load(context.Background()); err != nil {
			t.Fatal(err)
		}
		if err := poolRequest(restarted); err != nil || executor.calls.Load() != 1 {
			t.Fatalf("capability did not survive the restart: %v", err)
		}
	})
	t.Run("revoke-survives-restart", func(t *testing.T) {
		m, executor, _, _, _ := poolGuardFixture(t, "service")
		dir := m.runtimeConfigSnapshot().AuthDir
		if err := os.WriteFile(filepath.Join(dir, "synthetic-pool-account.json"), mustJSON(t, rawCodexCredential("synthetic-account-id")), 0o600); err != nil {
			t.Fatal(err)
		}
		poolRevoke(t, m)
		restarted := NewManager(&filestoreStyleStore{dir: dir}, nil, nil)
		restarted.SetConfig(m.runtimeConfigSnapshot())
		restarted.RegisterExecutor(executor)
		if err := restarted.Load(context.Background()); err != nil {
			t.Fatal(err)
		}
		_, states, err := restarted.PoolTrustSnapshot()
		if err != nil || len(states) != 1 || states[0].State != PoolTrustRevoked {
			t.Fatalf("revoked state did not survive the restart: %+v err=%v", states, err)
		}
		if err := poolRequest(restarted); err == nil || executor.calls.Load() != 0 {
			t.Fatal("revoked identity served after restart")
		}
	})
}

// TestPoolIdentityLegacyV1TrustNeverAdmits pins the v1 → v2 fail-closed
// migration: a legacy trusted record can load but never admit, surfaces as
// pending reauthorization, and legacy promotion commands are rejected.
func TestPoolIdentityLegacyV1TrustNeverAdmits(t *testing.T) {
	m, executor, auth, _, _ := poolGuardFixture(t, "service")
	// Rewrite the trusted journal record in place as a legacy v1 record: same
	// state/revision, digest from the old implicit algorithm, no version.
	data, err := os.ReadFile(m.poolGuard.checkpoint)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSuffix(string(data), "\n"), "\n")
	var last poolCheckpoint
	if err := json.Unmarshal([]byte(lines[len(lines)-1]), &last); err != nil {
		t.Fatal(err)
	}
	last.Trust[0].CredentialDigest = v1StyleDigest("legacy-implicit-digest")
	last.Trust[0].IdentityVersion = 0
	last.Integrity = poolCheckpointIntegrity(last)
	encoded, _ := json.Marshal(last)
	lines[len(lines)-1] = string(encoded)
	if err := os.WriteFile(m.poolGuard.checkpoint, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// The legacy record must not admit the still-running runtime auth.
	if err := poolRequest(m); err == nil || executor.calls.Load() != 0 {
		t.Fatal("legacy v1 trust admitted on the v2 identity")
	}
	// It must surface as pending reauthorization with the canonical digest.
	pending, err := m.PoolPendingIdentities()
	if err != nil || len(pending) != 1 {
		t.Fatalf("legacy identity missing from pending: %+v err=%v", pending, err)
	}
	if pending[0].CredentialDigest != PoolCredentialDigest(auth) || pending[0].IdentityVersion != CredentialSecurityIdentityVersion {
		t.Fatalf("pending expectation = %+v", pending[0])
	}
	// A promotion command presenting the legacy digest must be rejected.
	revision, _, errSnapshot := m.PoolTrustSnapshot()
	if errSnapshot != nil {
		t.Fatal(errSnapshot)
	}
	legacy := pending[0]
	legacy.CredentialDigest = v1StyleDigest("legacy-implicit-digest")
	if err := m.PromotePoolIdentities(context.Background(), PoolPromotion{ExpectedRevision: revision, Identities: []PoolIdentityExpectation{legacy}}); err == nil {
		t.Fatal("legacy v1 promotion command accepted")
	}
	// An unknown identity schema version must be rejected outright.
	unknown := pending[0]
	unknown.IdentityVersion = CredentialSecurityIdentityVersion + 1
	if err := m.PromotePoolIdentities(context.Background(), PoolPromotion{ExpectedRevision: revision, Identities: []PoolIdentityExpectation{unknown}}); err == nil {
		t.Fatal("unknown identity version accepted")
	}
	// The operator can recover only by re-promoting the canonical identity and
	// re-granting the capability under the new trust generation.
	if err := m.PromotePoolIdentities(context.Background(), PoolPromotion{ExpectedRevision: revision, Identities: []PoolIdentityExpectation{pending[0]}}); err != nil {
		t.Fatalf("canonical re-promotion rejected: %v", err)
	}
	rePromoted, _ := m.GetByID(auth.ID)
	if rePromoted == nil {
		t.Fatal("re-promoted identity vanished")
	}
	if err := grantPoolModelCapability(t, m, rePromoted, "synthetic-native"); err != nil {
		t.Fatalf("capability re-grant rejected: %v", err)
	}
	if err := poolRequest(m); err != nil || executor.calls.Load() != 1 {
		t.Fatalf("re-promoted identity did not admit: %v", err)
	}
}

// TestPoolIdentityWatcherReloadStable pins rapid watcher reload semantics:
// repeated synthesis of the same credential, with non-identity metadata churn,
// must not produce a second identity or burn trust.
func TestPoolIdentityWatcherReloadStable(t *testing.T) {
	m, executor, _, _, _ := poolGuardFixture(t, "service")
	auth, _ := m.GetByID("synthetic-pool-account")
	if auth == nil {
		t.Fatal("fixture account missing")
	}
	for i := 0; i < 5; i++ {
		reloaded := watcherStyleCodexAuth("synthetic-dir", "synthetic-pool-account.json", "synthetic-account-id")
		reloaded.ID = auth.ID
		reloaded.Generation = 0
		reloaded.Metadata["last_refresh"] = time.Now().Format(time.RFC3339)
		reloaded.Metadata["access_token"] = "staging-access-token-" + time.Now().Format(time.RFC3339Nano)
		updated, err := m.Update(context.Background(), reloaded)
		if err != nil {
			t.Fatalf("watcher reload %d rejected: %v", i, err)
		}
		if updated.Disabled {
			t.Fatalf("watcher reload %d quarantined the account", i)
		}
		if _, err := m.Update(context.Background(), auth.Clone()); err != nil {
			t.Fatalf("filestore-style reload %d rejected: %v", i, err)
		}
	}
	_, states, err := m.PoolTrustSnapshot()
	if err != nil || len(states) != 1 || states[0].State != PoolTrustTrusted || states[0].IdentityVersion != CredentialSecurityIdentityVersion {
		t.Fatalf("watcher reload churned trust: %+v err=%v", states, err)
	}
	if err := poolRequest(m); err != nil || executor.calls.Load() != 1 {
		t.Fatalf("admission lost after reload churn: %v", err)
	}
}

// TestPoolIdentityLeaseAndSnapshotBindCanonicalDigest pins the dispatch fence,
// lease, and management snapshot to the canonical identity implementation.
func TestPoolIdentityLeaseAndSnapshotBindCanonicalDigest(t *testing.T) {
	m, _, auth, _, _ := poolGuardFixture(t, "service")
	probe := &poolProbeExecutor{stream: make(chan cliproxyexecutor.StreamChunk, 1)}
	probe.stream <- cliproxyexecutor.StreamChunk{Payload: []byte(`data: {"type":"response.output_text.delta","delta":"synthetic"}` + "\n\n")}
	m.RegisterExecutor(probe)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result, err := m.ExecuteStream(ctx, []string{"codex"}, cliproxyexecutor.Request{Model: "synthetic-native"}, cliproxyexecutor.Options{Stream: true})
	if err != nil {
		t.Fatal(err)
	}
	inFlight := m.PoolInFlightSnapshot()
	if len(inFlight) != 1 {
		t.Fatalf("in-flight snapshot = %+v", inFlight)
	}
	if inFlight[0].CredentialDigest == "" || inFlight[0].CredentialDigest != PoolCredentialDigest(auth) {
		t.Fatal("lease is not bound to the canonical credential digest")
	}
	_, states, err := m.PoolTrustSnapshot()
	if err != nil || len(states) != 1 {
		t.Fatalf("trust snapshot failed: %v", err)
	}
	if states[0].CredentialDigest != PoolCredentialDigest(auth) || states[0].IdentityVersion != CredentialSecurityIdentityVersion {
		t.Fatal("management trust snapshot is not bound to the canonical identity")
	}
	_, capabilities, err := m.PoolModelSnapshot()
	if err != nil || len(capabilities) != 1 || capabilities[0].CredentialDigest != PoolCredentialDigest(auth) || capabilities[0].IdentityVersion != CredentialSecurityIdentityVersion {
		t.Fatalf("capability snapshot is not bound to the canonical identity: %+v err=%v", capabilities, err)
	}
	if pending, errPending := m.PoolPendingIdentities(); errPending != nil || len(pending) != 0 {
		t.Fatalf("pending identities after promotion: %+v err=%v", pending, errPending)
	}
	cancel()
	for range result.Chunks {
	}
	registry.GetGlobalRegistry().UnregisterClient(auth.ID)
}

func mustJSON(t *testing.T, value any) []byte {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return data
}
