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

// TestPG02TrustPromotionOverridesDisable validates whether Trust promotion
// overwrites a formally disabled account's state.
func TestPG02TrustPromotionOverridesDisable(t *testing.T) {
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
		ID:       "trust-override-test.json",
		Provider: "codex",
		FileName: "trust-override-test.json",
		Status:   coreauth.StatusActive,
		Attributes: map[string]string{
			coreauth.AttributeAuthKind: coreauth.AuthKindOAuth,
			"plan_type":                "pro",
		},
		Metadata: map[string]any{
			"type":         "codex",
			"access_token": "synthetic-unused",
			"account_id":   "trust-test-account",
			"email":        "trust@test.invalid",
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
	m := coreauth.NewManager(store, nil, nil)
	m.SetConfig(cfg)
	m.RegisterExecutor(&syncTestExecutor{})

	a, err = m.Register(ctx, a)
	if err != nil {
		t.Fatal(err)
	}

	s := &Service{cfg: cfg, coreManager: m}
	m.SetPoolRegistrySync(s.syncPoolRegistry)
	t.Cleanup(func() { registry.GetGlobalRegistry().UnregisterClient(a.ID) })

	// Ensure account is persisted to disk first
	current, _ := m.GetByID(a.ID)
	if _, err := store.Save(coreauth.WithAuthCreationIntent(ctx), current); err != nil {
		t.Fatalf("Initial save failed: %v", err)
	}

	// Verify file exists before proceeding
	authPath := filepath.Join(dir, a.FileName)
	if _, errStat := os.Stat(authPath); errStat != nil {
		t.Fatalf("Auth file not created: %v", errStat)
	}

	// Step 1: Formally disable the account
	current.Disabled = true
	current.Status = coreauth.StatusDisabled
	current.StatusMessage = "disabled before trust promotion"

	updated, err := m.Update(ctx, current)
	if err != nil {
		t.Fatalf("Update() failed: %v", err)
	}
	if !updated.Disabled {
		t.Fatal("Update() returned non-disabled account")
	}

	// Verify file has disabled=true
	raw, err := os.ReadFile(authPath)
	if err != nil {
		t.Fatal(err)
	}
	var metadata map[string]any
	if err := json.Unmarshal(raw, &metadata); err != nil {
		t.Fatal(err)
	}
	disabledBefore, ok := metadata["disabled"].(bool)
	if !ok || !disabledBefore {
		t.Fatalf("file does not contain disabled=true before promotion: disabled=%v ok=%v", disabledBefore, ok)
	}

	t.Logf("✓ Account disabled: file disabled=%v", disabledBefore)

	// Step 2: Execute Trust promotion on the disabled account
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

	t.Logf("✓ Trust promotion executed")

	// Step 3: Check if disabled state was preserved
	raw2, err := os.ReadFile(authPath)
	if err != nil {
		t.Fatal(err)
	}
	var metadata2 map[string]any
	if err := json.Unmarshal(raw2, &metadata2); err != nil {
		t.Fatal(err)
	}
	disabledAfter, ok := metadata2["disabled"].(bool)
	if !ok {
		t.Fatalf("file lost disabled field after promotion")
	}

	t.Logf("After Trust promotion: file disabled=%v", disabledAfter)

	afterPromotion, _ := m.GetByID(a.ID)
	t.Logf("After Trust promotion: memory Disabled=%v Status=%s", afterPromotion.Disabled, afterPromotion.Status)

	// Verify: Trust promotion should NOT overwrite disabled=true
	if !disabledAfter {
		t.Errorf("SECURITY FAILURE: Trust promotion overwrote disabled=true → disabled=false in file")
	}

	if !afterPromotion.Disabled {
		t.Errorf("SECURITY FAILURE: Trust promotion changed Disabled=true → Disabled=false in memory")
	}

	// Step 4: Verify isolation is maintained after promotion
	p, e := m.PoolRequestPreflight(ctx, "gpt-5.6-luna", ex.Options{
		OriginalRequest: []byte(`{"model":"gpt-5.6-luna","tools":[]}`),
	})

	if e == nil && p.EligibleCount != 0 {
		t.Errorf("SECURITY FAILURE: disabled account became eligible after Trust promotion: eligible=%d", p.EligibleCount)
	}

	if err := s.syncPoolRegistry(ctx); err != nil {
		t.Logf("Registry sync error (expected for disabled): %v", err)
	}

	models := registry.GetGlobalRegistry().GetModelsForClient(a.ID)
	if len(models) != 0 {
		t.Errorf("SECURITY FAILURE: disabled account published models after Trust promotion: count=%d", len(models))
	}

	t.Logf("✓ Isolation maintained: eligible=%d models=%d", p.EligibleCount, len(models))
}
