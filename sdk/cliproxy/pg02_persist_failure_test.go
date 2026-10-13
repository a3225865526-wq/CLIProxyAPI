package cliproxy

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	filestore "github.com/router-for-me/CLIProxyAPI/v8/sdk/auth"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
)

// mockFailingStore wraps FileTokenStore and injects save failures.
type mockFailingStore struct {
	*filestore.FileTokenStore
	shouldFail bool
}

func (m *mockFailingStore) Save(ctx context.Context, auth *coreauth.Auth) (string, error) {
	if m.shouldFail {
		return "", errors.New("injected persist failure")
	}
	return m.FileTokenStore.Save(ctx, auth)
}

// TestPG02PersistFailureIsolationRisk validates Manager.Update behavior
// when persist fails - does it return error or silently succeed?
func TestPG02PersistFailureIsolationRisk(t *testing.T) {
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

	// Directly write enabled account file
	authFile := "persist-failure-test.json"
	authPath := filepath.Join(dir, authFile)
	metadata := map[string]any{
		"type":         "codex",
		"access_token": "synthetic-unused",
		"account_id":   "persist-test",
		"email":        "persist@test.invalid",
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
			CredentialDigest: "",
			Models:           []string{"gpt-5.6-luna"},
			Capabilities:     []string{"text_chat"},
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
	store := &mockFailingStore{FileTokenStore: baseStore, shouldFail: false}

	m := coreauth.NewManager(store, nil, nil)
	m.SetConfig(cfg)
	m.RegisterExecutor(&syncTestExecutor{})

	// Load from file
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

	t.Logf("Initial state: Disabled=%v Status=%s", a.Disabled, a.Status)

	// === Inject persist failure ===
	store.shouldFail = true

	a.Disabled = true
	a.Status = coreauth.StatusDisabled

	updated, errUpdate := m.Update(ctx, a)

	t.Logf("Update() with persist failure: error=%v", errUpdate)

	if errUpdate == nil {
		t.Logf("⚠ OBSERVATION: Update() succeeded despite persist failure")
		if updated != nil {
			t.Logf("Returned: Disabled=%v Status=%s", updated.Disabled, updated.Status)
		}
	} else {
		t.Logf("✓ Update() returned error: %v", errUpdate)
	}

	// Check file state
	rawAfter, _ := os.ReadFile(authPath)
	var metaAfter map[string]any
	json.Unmarshal(rawAfter, &metaAfter)
	disabledAfter, _ := metaAfter["disabled"].(bool)

	t.Logf("File state after Update: disabled=%v", disabledAfter)

	// Check memory state
	current, _ := m.GetByID(authFile)
	t.Logf("Memory state: Disabled=%v", current.Disabled)

	// === Report findings ===
	if errUpdate == nil && current.Disabled && !disabledAfter {
		t.Errorf("SECURITY DEFECT: Update() silently succeeded with state drift (memory Disabled=true, file disabled=false)")
	}
}
