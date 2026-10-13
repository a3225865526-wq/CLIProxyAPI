package cliproxy

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	filestore "github.com/router-for-me/CLIProxyAPI/v8/sdk/auth"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	ex "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
)

// TestPG02RealStartupRegistryBehavior validates Registry synchronization
// in a startup sequence that mimics service_lifecycle.go Run() method.
func TestPG02RealStartupRegistryBehavior(t *testing.T) {
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
		ID:       "startup-disabled-test.json",
		Provider: "codex",
		FileName: "startup-disabled-test.json",
		Status:   coreauth.StatusDisabled,
		Disabled: true,
		Attributes: map[string]string{
			coreauth.AttributeAuthKind: coreauth.AuthKindOAuth,
			"plan_type": "pro",
		},
		Metadata: map[string]any{
			"type":         "codex",
			"access_token": "synthetic-unused",
			"account_id":   "startup-test-account",
			"email":        "startup@test.invalid",
			"disabled":     true,
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

	// Write disabled account file directly
	authPath := filepath.Join(dir, a.FileName)
	authBody, err := json.Marshal(a.Metadata)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(authPath, authBody, 0600); err != nil {
		t.Fatal(err)
	}

	cfg := &config.Config{AuthDir: dir}
	store := filestore.NewFileTokenStore()
	store.SetBaseDir(dir)

	// === Simulate service_lifecycle.go Run() startup sequence ===

	// Step 1: Create Manager and set Pool Registry Sync (builder.go:299)
	m := coreauth.NewManager(store, nil, nil)
	m.SetConfig(cfg)
	m.RegisterExecutor(&syncTestExecutor{})

	s := &Service{cfg: cfg, coreManager: m}
	m.SetPoolRegistrySync(s.syncPoolRegistry)
	t.Cleanup(func() { registry.GetGlobalRegistry().UnregisterClient(a.ID) })

	// Step 2: Load accounts (service_lifecycle.go:78)
	if err := m.Load(ctx); err != nil {
		t.Fatal(err)
	}

	loaded, ok := m.GetByID(a.ID)
	if !ok {
		t.Fatal("account not loaded")
	}

	t.Logf("After Load: Disabled=%v Status=%s", loaded.Disabled, loaded.Status)

	// Step 3: Check Registry state WITHOUT explicit syncPoolRegistry call
	// This mimics real startup where Load() alone should establish correct state
	modelsAfterLoad := registry.GetGlobalRegistry().GetModelsForClient(a.ID)
	t.Logf("After Load (before any sync): models=%d", len(modelsAfterLoad))

	// Step 4: Check Preflight
	p, errPreflight := m.PoolRequestPreflight(ctx, "gpt-5.6-luna", ex.Options{
		OriginalRequest: []byte(`{"model":"gpt-5.6-luna","tools":[]}`),
	})
	t.Logf("After Load: preflight eligible=%d error=%v", p.EligibleCount, errPreflight)

	// Step 5: NOW call syncPoolRegistry explicitly (what happens if manually triggered)
	if err := s.syncPoolRegistry(ctx); err != nil {
		t.Logf("syncPoolRegistry error: %v", err)
	}

	modelsAfterSync := registry.GetGlobalRegistry().GetModelsForClient(a.ID)
	t.Logf("After explicit syncPoolRegistry: models=%d", len(modelsAfterSync))

	// === Verification ===

	if !loaded.Disabled {
		t.Error("SECURITY FAILURE: disabled account loaded as enabled")
	}

	if errPreflight == nil && p.EligibleCount != 0 {
		t.Errorf("SECURITY FAILURE: disabled account has preflight eligibility=%d", p.EligibleCount)
	}

	if len(modelsAfterSync) != 0 {
		t.Errorf("SECURITY FAILURE: disabled account published models after sync: count=%d", len(modelsAfterSync))
	}

	// Report findings
	t.Logf("✓ Final state: Disabled=%v eligible=%d models=%d", loaded.Disabled, p.EligibleCount, len(modelsAfterSync))

	if !loaded.Disabled || (errPreflight == nil && p.EligibleCount != 0) || len(modelsAfterSync) != 0 {
		t.Fatal("Disabled account isolation failed in startup sequence")
	}
}
