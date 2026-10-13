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

type testFailingStore struct {
	*filestore.FileTokenStore
	shouldFail bool
}

func (f *testFailingStore) Save(ctx context.Context, auth *coreauth.Auth) (string, error) {
	if f.shouldFail {
		return "", errors.New("injected persist failure")
	}
	return f.FileTokenStore.Save(ctx, auth)
}

// TestPG02PersistFailureFixed validates the fix for persist error handling
func TestPG02PersistFailureFixed(t *testing.T) {
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

	authFile := "persist-fix-test.json"
	authPath := filepath.Join(dir, authFile)

	// Create enabled account
	metadata := map[string]any{
		"type":         "codex",
		"access_token": "synthetic-token-fixed",
		"account_id":   "persist-fix-account",
		"email":        "fix@test.invalid",
		"disabled":     false,
	}
	metaBody, _ := json.Marshal(metadata)
	if err := os.WriteFile(authPath, metaBody, 0600); err != nil {
		t.Fatal(err)
	}

	// Create auth for digest calculation
	tempAuth := &coreauth.Auth{
		ID:       authFile,
		Provider: "codex",
		Metadata: metadata,
	}
	digest := coreauth.PoolCredentialDigest(tempAuth)

	record := coreauth.PoolGrantFile{
		GuardVersion: coreauth.PoolGuardVersion,
		Revision:     1,
		ExecutorID:   "synthetic-service",
		Grants: []coreauth.PoolGrant{{
			AuthID:           authFile,
			Provider:         "codex",
			CredentialDigest: digest,
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

	store := &testFailingStore{FileTokenStore: baseStore, shouldFail: false}

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

	t.Logf("After Load: Disabled=%v Status=%s", a.Disabled, a.Status)

	if a.Disabled {
		t.Fatalf("Account should be enabled after Load, got Disabled=%v", a.Disabled)
	}

	s := &Service{cfg: cfg, coreManager: m}
	m.SetPoolRegistrySync(s.syncPoolRegistry)
	t.Cleanup(func() { registry.GetGlobalRegistry().UnregisterClient(a.ID) })

	// === Test: Persist failure on disable ===
	store.shouldFail = true

	a.Disabled = true
	a.Status = coreauth.StatusDisabled

	updated, errUpdate := m.Update(ctx, a)

	t.Logf("Update() with persist failure: error=%v", errUpdate)

	if errUpdate == nil {
		t.Errorf("FAILED: Update() should return error when persist fails during Disabled state change")

		rawFile, _ := os.ReadFile(authPath)
		var metaFile map[string]any
		json.Unmarshal(rawFile, &metaFile)
		disabledFile, _ := metaFile["disabled"].(bool)

		t.Logf("State after Update: memory Disabled=%v, file disabled=%v",
			updated.Disabled, disabledFile)

		if updated.Disabled && !disabledFile {
			t.Errorf("STATE DRIFT: memory and file inconsistent")
		}
	} else {
		t.Logf("✓ FIXED: Update() correctly returned error: %v", errUpdate)

		// Failed persistence still requires runtime isolation.
		current, _ := m.GetByID(authFile)
		if !current.Disabled || !coreauth.ManagementIsolation(current) {
			t.Errorf("Failed disable lost runtime isolation")
		} else {
			t.Logf("✓ Failed disable retained runtime isolation")
		}

		// Verify file unchanged
		rawFile, _ := os.ReadFile(authPath)
		var metaFile map[string]any
		json.Unmarshal(rawFile, &metaFile)
		disabledFile, _ := metaFile["disabled"].(bool)

		if disabledFile {
			t.Errorf("File should remain disabled=false, got %v", disabledFile)
		} else {
			t.Logf("✓ File correctly remains disabled=false")
		}
	}
}
