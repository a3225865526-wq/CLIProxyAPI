package cliproxy

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
	filestore "github.com/router-for-me/CLIProxyAPI/v8/sdk/auth"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/config"
)

// failingStore wraps FileTokenStore and can inject save failures
type failingStore struct {
	*filestore.FileTokenStore
	shouldFail bool
}

func (f *failingStore) Save(ctx context.Context, auth *coreauth.Auth) (string, error) {
	if f.shouldFail {
		return "", errors.New("injected persist failure")
	}
	return f.FileTokenStore.Save(ctx, auth)
}

// TestPG02ManagerUpdateStateOrder validates the order of state changes
// in Manager.Update to ensure no unsafe intermediate states.
func TestPG02ManagerUpdateStateOrder(t *testing.T) {
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

	// Write enabled account file with EXPLICIT disabled=false
	authFile := "state-order-test.json"
	authPath := filepath.Join(dir, authFile)
	metadata := map[string]any{
		"type":         "codex",
		"access_token": "synthetic-unused",
		"account_id":   "state-order-test",
		"email":        "order@test.invalid",
		"disabled":     false,
	}
	metaBody, _ := json.Marshal(metadata)
	if err := os.WriteFile(authPath, metaBody, 0600); err != nil {
		t.Fatal(err)
	}

	record := coreauth.PoolGrantFile{
		GuardVersion: coreauth.PoolGuardVersion,
		Revision:     1,
		ExecutorID:   "synthetic-service",
		Grants: []coreauth.PoolGrant{{
			AuthID:           authFile,
			Provider:         "codex",
			CredentialDigest: coreauth.PoolCredentialDigest(&coreauth.Auth{ID: authFile, Provider: "codex", Metadata: metadata}),
			Models:           []string{"gpt-5.6-luna"},
			Capabilities:     []string{"text_chat", "exact_usage"},
			Enabled:          true,
			MaxConcurrency:   1,
			ExpiresAt:        time.Now().Add(25 * time.Minute).Unix(),
			SourceEvidence:   []string{"synthetic-source"},
			TestEvidence:     []string{"synthetic-test"},
		}},
	}

	body, _ := json.Marshal(record)
	if err := os.WriteFile(grants, body, 0600); err != nil {
		t.Fatal(err)
	}

	cfg := &config.Config{AuthDir: dir}
	store := filestore.NewFileTokenStore()
	store.SetBaseDir(dir)

	m := coreauth.NewManager(store, nil, nil)
	m.SetConfig(cfg)
	m.RegisterExecutor(&syncTestExecutor{})

	if err := m.Load(ctx); err != nil {
		t.Fatal(err)
	}

	a, ok := m.GetByID(authFile)
	if !ok {
		t.Fatal("account not loaded")
	}

	s := &Service{cfg: cfg, coreManager: m}
	m.SetPoolRegistrySync(s.syncPoolRegistry)
	t.Cleanup(func() { registry.GetGlobalRegistry().UnregisterClient(a.ID) })

	t.Logf("Initial state: Disabled=%v", a.Disabled)

	// Publish models first
	if err := s.syncPoolRegistry(ctx); err != nil {
		t.Fatal(err)
	}

	modelsBeforeDisable := registry.GetGlobalRegistry().GetModelsForClient(a.ID)
	t.Logf("Before disable: models=%d", len(modelsBeforeDisable))

	// Test: Successful disable
	a.Disabled = true
	a.Status = coreauth.StatusDisabled

	updated, errUpdate := m.Update(ctx, a)
	if errUpdate != nil {
		t.Fatalf("Update() failed: %v", errUpdate)
	}

	t.Logf("After Update: memory Disabled=%v", updated.Disabled)

	// Check file state
	rawAfter, _ := os.ReadFile(authPath)
	var metaAfter map[string]any
	json.Unmarshal(rawAfter, &metaAfter)
	disabledFile, _ := metaAfter["disabled"].(bool)
	t.Logf("After Update: file disabled=%v", disabledFile)

	// Check Registry
	if err := s.syncPoolRegistry(ctx); err != nil {
		t.Logf("syncPoolRegistry: %v", err)
	}
	modelsAfterDisable := registry.GetGlobalRegistry().GetModelsForClient(a.ID)
	t.Logf("After disable: models=%d", len(modelsAfterDisable))

	// Verify consistency
	if !updated.Disabled || !disabledFile || len(modelsAfterDisable) != 0 {
		t.Errorf("State inconsistency: memory=%v file=%v models=%d",
			updated.Disabled, disabledFile, len(modelsAfterDisable))
	} else {
		t.Logf("✓ Memory, file, and Registry consistent after disable")
	}
}

// TestPG02ManagerUpdateErrorPropagation validates Manager.Update error handling
func TestPG02ManagerUpdateErrorPropagation(t *testing.T) {
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

	authFile := "error-prop-test.json"
	authPath := filepath.Join(dir, authFile)
	metadata := map[string]any{
		"type":         "codex",
		"access_token": "synthetic-unused",
		"account_id":   "error-prop-test",
		"email":        "error@test.invalid",
		"disabled":     false,
	}
	metaBody, _ := json.Marshal(metadata)
	if err := os.WriteFile(authPath, metaBody, 0600); err != nil {
		t.Fatal(err)
	}

	record := coreauth.PoolGrantFile{
		GuardVersion: coreauth.PoolGuardVersion,
		Revision:     1,
		ExecutorID:   "synthetic-service",
		Grants: []coreauth.PoolGrant{{
			AuthID:           authFile,
			Provider:         "codex",
			CredentialDigest: coreauth.PoolCredentialDigest(&coreauth.Auth{ID: authFile, Provider: "codex", Metadata: metadata}),
			Models:           []string{"gpt-5.6-luna"},
			Capabilities:     []string{"text_chat", "exact_usage"},
			Enabled:          true,
			MaxConcurrency:   1,
			ExpiresAt:        time.Now().Add(25 * time.Minute).Unix(),
			SourceEvidence:   []string{"synthetic-source"},
			TestEvidence:     []string{"synthetic-test"},
		}},
	}

	body, _ := json.Marshal(record)
	if err := os.WriteFile(grants, body, 0600); err != nil {
		t.Fatal(err)
	}

	cfg := &config.Config{AuthDir: dir}
	baseStore := filestore.NewFileTokenStore()
	baseStore.SetBaseDir(dir)

	// Wrap with failing store
	store := &failingStore{FileTokenStore: baseStore, shouldFail: false}

	m := coreauth.NewManager(store, nil, nil)
	m.SetConfig(cfg)
	m.RegisterExecutor(&syncTestExecutor{})

	if err := m.Load(ctx); err != nil {
		t.Fatal(err)
	}

	a, ok := m.GetByID(authFile)
	if !ok {
		t.Fatal("account not loaded")
	}

	a = pg02AdmitRegressionAuth(t, m, a)

	t.Logf("Initial state after Load: Disabled=%v", a.Disabled)

	// Verify account loaded as enabled
	if a.Disabled {
		t.Fatalf("Account should load as enabled, got Disabled=%v", a.Disabled)
	}

	s := &Service{cfg: cfg, coreManager: m}
	m.SetPoolRegistrySync(s.syncPoolRegistry)
	t.Cleanup(func() { registry.GetGlobalRegistry().UnregisterClient(a.ID) })

	// Enable persist failure
	store.shouldFail = true

	// Attempt to disable
	a.Disabled = true
	a.Status = coreauth.StatusDisabled

	updated, errUpdate := m.Update(ctx, a)

	t.Logf("Update() with persist failure: error=%v", errUpdate)

	if errUpdate == nil {
		t.Errorf("DEFECT: Update() should return error when persist fails on Disabled state change")

		// Check state drift
		rawFile, _ := os.ReadFile(authPath)
		var metaFile map[string]any
		json.Unmarshal(rawFile, &metaFile)
		disabledFile, _ := metaFile["disabled"].(bool)

		if updated != nil && updated.Disabled && !disabledFile {
			t.Errorf("STATE DRIFT: memory Disabled=%v, file disabled=%v",
				updated.Disabled, disabledFile)
		}
	} else {
		t.Logf("✓ Update() correctly returned error: %v", errUpdate)

		// Failed persistence still requires runtime isolation.
		current, _ := m.GetByID(authFile)
		if !current.Disabled || !coreauth.ManagementIsolation(current) {
			t.Errorf("Failed disable lost runtime isolation")
		} else {
			t.Logf("✓ Failed disable retained runtime isolation")
		}
	}
}
