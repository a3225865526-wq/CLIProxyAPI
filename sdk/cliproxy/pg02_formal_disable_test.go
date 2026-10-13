package cliproxy

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
	filestore "github.com/router-for-me/CLIProxyAPI/v8/sdk/auth"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	ex "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/config"
)

// TestPG02FormalDisablePreservesIsolation validates that formal management
// API disable (without WithSkipPersist) preserves isolation across restart.
func TestPG02FormalDisablePreservesIsolation(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	dir := filepath.Join(root, "auths")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	grants := filepath.Join(root, "grants.json")
	checkpoint := filepath.Join(root, "checkpoint.jsonl")

	t.Setenv("CLEARAPI_POOL_ROLE", "service")
	t.Setenv("CLEARAPI_POOL_ADMISSION_FILE", grants)
	t.Setenv("CLEARAPI_POOL_EXECUTOR_ID", "synthetic-service")
	t.Setenv("CLEARAPI_POOL_CHECKPOINT_FILE", checkpoint)

	if err := coreauth.ProvisionPoolCheckpoint(checkpoint, "synthetic-service"); err != nil {
		t.Fatal(err)
	}

	a := &coreauth.Auth{
		ID:       "synthetic-formal-disable.json",
		Provider: "codex",
		FileName: "synthetic-formal-disable.json",
		Status:   coreauth.StatusActive,
		Attributes: map[string]string{
			coreauth.AttributeAuthKind: coreauth.AuthKindOAuth,
			"plan_type":                "pro",
		},
		Metadata: map[string]any{
			"type":         "codex",
			"access_token": "synthetic-unused",
			"account_id":   "synthetic-account",
			"email":        "formal@test.invalid",
		},
	}

	record := coreauth.PoolGrantFile{
		GuardVersion: coreauth.PoolGuardVersion,
		Revision:     1,
		ExecutorID:   "synthetic-service",
		Grants: []coreauth.PoolGrant{{
			AuthID:           a.ID,
			Provider:         a.Provider,
			CredentialDigest: coreauth.PoolCredentialDigest(a),
			Models:           []string{"gpt-5.6-luna"},
			Capabilities:     []string{"text_chat", "stream_text", "exact_usage"},
			Enabled:          true,
			MaxConcurrency:   1,
			ExpiresAt:        time.Now().Add(25 * time.Minute).Unix(),
			SourceEvidence:   []string{"synthetic-source"},
			TestEvidence:     []string{"synthetic-test"},
		}},
	}

	body, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(grants, body, 0600); err != nil {
		t.Fatal(err)
	}

	cfg := &config.Config{AuthDir: dir}
	store := filestore.NewFileTokenStore()
	store.SetBaseDir(dir)
	if _, err = store.Save(coreauth.WithAuthCreationIntent(ctx), a); err != nil {
		t.Fatal(err)
	}
	m := coreauth.NewManager(store, nil, nil)
	m.SetConfig(cfg)
	m.RegisterExecutor(&syncTestExecutor{})

	// Register and promote to establish Trust + Grant
	a, err = m.Register(ctx, a)
	if err != nil {
		t.Fatal(err)
	}

	s := &Service{cfg: cfg, coreManager: m}
	m.SetPoolRegistrySync(s.syncPoolRegistry)
	t.Cleanup(func() { registry.GetGlobalRegistry().UnregisterClient(a.ID) })

	expectation := func() (uint64, coreauth.PoolIdentityExpectation) {
		rev, states, e := m.PoolTrustSnapshot()
		if e != nil {
			t.Fatal(e)
		}
		for _, st := range states {
			if st.AuthID == a.ID {
				return rev, coreauth.PoolIdentityExpectation{
					AuthID:           a.ID,
					Provider:         a.Provider,
					CredentialDigest: coreauth.PoolCredentialDigest(a),
					Generation:       st.Generation,
				}
			}
		}
		return rev, coreauth.PoolIdentityExpectation{
			AuthID:           a.ID,
			Provider:         a.Provider,
			CredentialDigest: coreauth.PoolCredentialDigest(a),
		}
	}

	rev, identity := expectation()
	if err = m.PromotePoolIdentities(ctx, coreauth.PoolPromotion{
		ExpectedRevision: rev,
		Identities:       []coreauth.PoolIdentityExpectation{identity},
	}); err != nil {
		t.Fatal(err)
	}

	rev, identity = expectation()
	if err = m.GrantPoolModelCapability(ctx, coreauth.PoolModelGrant{
		ExpectedRevision: rev,
		Identity:         identity,
		Model:            "gpt-5.6-luna",
	}); err != nil {
		t.Fatal(err)
	}

	// Verify account is admitted
	p, e := m.PoolRequestPreflight(ctx, "gpt-5.6-luna", ex.Options{
		OriginalRequest: []byte(`{"model":"gpt-5.6-luna","tools":[]}`),
	})
	if e != nil || p.EligibleCount != 1 {
		t.Fatalf("account not admitted after promotion: %+v %v", p, e)
	}

	// Formal management disable (normal ctx, persist must succeed)
	current, _ := m.GetByID(a.ID)
	current.Disabled = true
	current.Status = coreauth.StatusDisabled
	current.StatusMessage = "disabled via test management API"

	// This is the FORMAL disable path - no WithSkipPersist
	updated, err := m.Update(ctx, current)
	if err != nil {
		t.Fatalf("Update() failed: %v", err)
	}
	if !updated.Disabled {
		t.Fatal("Update() returned non-disabled account")
	}

	// Verify persist actually wrote to disk
	persisted, err := store.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(persisted) != 1 || !persisted[0].Disabled {
		t.Fatalf("persist did not write disabled=true: got %d auths, disabled=%v",
			len(persisted), len(persisted) > 0 && persisted[0].Disabled)
	}

	// Check file content directly
	authPath := filepath.Join(dir, a.FileName)
	raw, err := os.ReadFile(authPath)
	if err != nil {
		t.Fatal(err)
	}
	var metadata map[string]any
	if err := json.Unmarshal(raw, &metadata); err != nil {
		t.Fatal(err)
	}
	disabledValue, ok := metadata["disabled"].(bool)
	if !ok || !disabledValue {
		t.Fatalf("file does not contain disabled=true: disabled=%v ok=%v", disabledValue, ok)
	}

	t.Logf("✓ Formal disable persisted: file disabled=%v", disabledValue)

	// Simulate restart: create new manager and load from disk
	m2 := coreauth.NewManager(store, nil, nil)
	m2.SetConfig(cfg)
	m2.RegisterExecutor(&syncTestExecutor{})
	s2 := &Service{cfg: cfg, coreManager: m2}
	m2.SetPoolRegistrySync(s2.syncPoolRegistry)

	if err := m2.Load(ctx); err != nil {
		t.Fatal(err)
	}

	// Trigger Registry sync (simulates full startup)
	if err := s2.syncPoolRegistry(ctx); err != nil {
		t.Fatal(err)
	}

	loaded, _ := m2.GetByID(a.ID)
	if loaded == nil {
		t.Fatal("account not loaded after restart")
	}

	t.Logf("After restart: Disabled=%v Status=%s", loaded.Disabled, loaded.Status)

	// Verify isolation is preserved
	if !loaded.Disabled {
		t.Error("SECURITY FAILURE: disabled account loaded as enabled after restart")
	}

	p2, e2 := m2.PoolRequestPreflight(ctx, "gpt-5.6-luna", ex.Options{
		OriginalRequest: []byte(`{"model":"gpt-5.6-luna","tools":[]}`),
	})

	if e2 == nil && p2.EligibleCount != 0 {
		t.Errorf("SECURITY FAILURE: disabled account regained admission: eligible=%d", p2.EligibleCount)
	}

	models := registry.GetGlobalRegistry().GetModelsForClient(a.ID)
	if len(models) != 0 {
		t.Errorf("SECURITY FAILURE: disabled account published models: count=%d", len(models))
	}

	t.Logf("✓ Isolation preserved after restart: eligible=%d models=%d", p2.EligibleCount, len(models))
}
