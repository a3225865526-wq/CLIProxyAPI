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
)

type mockFailStore struct {
	*filestore.FileTokenStore
	shouldFail bool
}

func (f *mockFailStore) Save(ctx context.Context, auth *coreauth.Auth) (string, error) {
	if f.shouldFail {
		return "", errors.New("injected persist failure")
	}
	return f.FileTokenStore.Save(ctx, auth)
}

// TestPG02PersistErrorHandling validates the fix ensures persist errors
// on Disabled state changes are propagated while runtime isolation remains fail-closed.
func TestPG02PersistErrorHandling(t *testing.T) {
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

	// Create account
	a := &coreauth.Auth{
		ID:       "persist-error-test.json",
		Provider: "codex",
		FileName: "persist-error-test.json",
		Status:   coreauth.StatusActive,
		Attributes: map[string]string{
			coreauth.AttributeAuthKind: coreauth.AuthKindOAuth,
		},
		Metadata: map[string]any{
			"type":         "codex",
			"access_token": "synthetic-token",
			"account_id":   "persist-error-account",
			"email":        "error@test.invalid",
			"disabled":     false,
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

	store := &mockFailStore{FileTokenStore: baseStore, shouldFail: false}

	m := coreauth.NewManager(store, nil, nil)
	m.SetConfig(cfg)
	m.RegisterExecutor(&syncTestExecutor{})

	// Register account
	registered, err := m.Register(ctx, a)
	if err != nil {
		t.Fatal(err)
	}

	registered = pg02AdmitRegressionAuth(t, m, registered)

	// Verify account is enabled
	current, _ := m.GetByID(registered.ID)
	if current.Disabled {
		t.Fatalf("Account should be enabled after promotion, got Disabled=%v", current.Disabled)
	}

	t.Logf("Account enabled and promoted: Disabled=%v", current.Disabled)

	// === Test: Inject persist failure and attempt disable ===
	store.shouldFail = true

	current.Disabled = true
	current.Status = coreauth.StatusDisabled

	updated, errUpdate := m.Update(ctx, current)

	t.Logf("Update() with persist failure: error=%v", errUpdate)

	if errUpdate == nil {
		t.Errorf("FAILED: Update() should return error when persist fails on Disabled state change")

		// Check for state drift
		authPath := filepath.Join(dir, registered.FileName)
		rawFile, _ := os.ReadFile(authPath)
		var metaFile map[string]any
		json.Unmarshal(rawFile, &metaFile)
		disabledFile, _ := metaFile["disabled"].(bool)

		t.Logf("State: memory Disabled=%v, file disabled=%v", updated.Disabled, disabledFile)

		if updated.Disabled && !disabledFile {
			t.Errorf("STATE DRIFT DETECTED: memory disabled but file enabled")
		}
	} else {
		t.Logf("✓ FIXED: Update() correctly returned error: %v", errUpdate)

		// A failed durable disable must retain runtime isolation.
		rolledBack, _ := m.GetByID(registered.ID)
		if !rolledBack.Disabled || !coreauth.ManagementIsolation(rolledBack) {
			t.Errorf("Failed disable lost runtime isolation")
		} else {
			t.Logf("✓ Failed disable retained runtime isolation")
		}

		// Verify file unchanged
		authPath := filepath.Join(dir, registered.FileName)
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
