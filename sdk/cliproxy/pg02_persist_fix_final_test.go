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

type failOnDemandStore struct {
	*filestore.FileTokenStore
	shouldFail bool
}

func (f *failOnDemandStore) Save(ctx context.Context, auth *coreauth.Auth) (string, error) {
	if f.shouldFail {
		return "", errors.New("injected persist failure")
	}
	return f.FileTokenStore.Save(ctx, auth)
}

// TestPG02PersistErrorFixed validates that the fix prevents state drift
// when persist fails during Disabled state change.
func TestPG02PersistErrorFixed(t *testing.T) {
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
		ID:       "persist-fix-auth.json",
		Provider: "codex",
		FileName: "persist-fix-auth.json",
		Status:   coreauth.StatusActive,
		Attributes: map[string]string{
			coreauth.AttributeAuthKind: coreauth.AuthKindOAuth,
			"plan_type":                "pro",
		},
		Metadata: map[string]any{
			"type":         "codex",
			"access_token": "synthetic-unused",
			"account_id":   "persist-fix-account",
			"email":        "fix@test.invalid",
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

	store := &failOnDemandStore{FileTokenStore: baseStore, shouldFail: false}

	m := coreauth.NewManager(store, nil, nil)
	m.SetConfig(cfg)
	m.RegisterExecutor(&syncTestExecutor{})

	a, err := m.Register(ctx, a)
	if err != nil {
		t.Fatal(err)
	}

	// Promote to trusted
	rev, identity := func() (uint64, coreauth.PoolIdentityExpectation) {
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
	}()

	if err := m.PromotePoolIdentities(ctx, coreauth.PoolPromotion{
		ExpectedRevision: rev,
		Identities:       []coreauth.PoolIdentityExpectation{identity},
	}); err != nil {
		t.Fatal(err)
	}

	// Grant model capability
	rev, identity = func() (uint64, coreauth.PoolIdentityExpectation) {
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
		return rev, coreauth.PoolIdentityExpectation{}
	}()

	if err := m.GrantPoolModelCapability(ctx, coreauth.PoolModelGrant{
		ExpectedRevision: rev,
		Identity:         identity,
		Model:            "gpt-5.6-luna",
	}); err != nil {
		t.Fatal(err)
	}

	// Verify account is enabled
	current, _ := m.GetByID(a.ID)
	if current.Disabled {
		t.Fatalf("Account should be enabled, got Disabled=%v", current.Disabled)
	}

	t.Logf("Account promoted and enabled: Disabled=%v", current.Disabled)

	// === Test: Inject persist failure and attempt disable ===
	store.shouldFail = true

	current.Disabled = true
	current.Status = coreauth.StatusDisabled

	updated, errUpdate := m.Update(ctx, current)

	t.Logf("Update() with persist failure: error=%v", errUpdate)

	if errUpdate == nil {
		t.Errorf("❌ FAILED: Update() should return error when persist fails on Disabled state change")

		authPath := filepath.Join(dir, a.FileName)
		rawFile, _ := os.ReadFile(authPath)
		var metaFile map[string]any
		json.Unmarshal(rawFile, &metaFile)
		disabledFile, _ := metaFile["disabled"].(bool)

		t.Logf("State: memory Disabled=%v, file disabled=%v", updated.Disabled, disabledFile)

		if updated.Disabled && !disabledFile {
			t.Errorf("❌ STATE DRIFT: memory disabled but file enabled")
		}
	} else {
		t.Logf("✅ FIXED: Update() correctly returned error: %v", errUpdate)

		// A store error does not prove that disk was unchanged. The P0 safety
		// contract requires runtime isolation, not a rollback to dispatchable.
		rolledBack, _ := m.GetByID(a.ID)
		if !rolledBack.Disabled {
			t.Errorf("failed disable must remain isolated, got Disabled=%v", rolledBack.Disabled)
		}

		// Verify file unchanged
		authPath := filepath.Join(dir, a.FileName)
		rawFile, _ := os.ReadFile(authPath)
		var metaFile map[string]any
		json.Unmarshal(rawFile, &metaFile)
		disabledFile, _ := metaFile["disabled"].(bool)

		if disabledFile {
			t.Errorf("❌ File should remain disabled=false, got %v", disabledFile)
		} else {
			t.Logf("✅ File correctly remains disabled=false")
		}
	}
}
