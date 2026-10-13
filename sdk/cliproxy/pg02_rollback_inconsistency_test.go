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
	ex "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/config"
)

type injectFailStore struct {
	*filestore.FileTokenStore
	shouldFail bool
}

func (f *injectFailStore) Save(ctx context.Context, auth *coreauth.Auth) (string, error) {
	if f.shouldFail {
		return "", errors.New("injected persist failure")
	}
	return f.FileTokenStore.Save(ctx, auth)
}

// TestPG02RollbackSchedulerInconsistency validates rollback behavior
// when persist fails AFTER Scheduler has been updated.
func TestPG02RollbackSchedulerInconsistency(t *testing.T) {
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
		ID:       "rollback-test.json",
		Provider: "codex",
		FileName: "rollback-test.json",
		Status:   coreauth.StatusActive,
		Attributes: map[string]string{
			coreauth.AttributeAuthKind: coreauth.AuthKindOAuth,
		},
		Metadata: map[string]any{
			"type":         "codex",
			"access_token": "synthetic-token",
			"account_id":   "rollback-account",
			"email":        "rollback@test.invalid",
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

	store := &injectFailStore{FileTokenStore: baseStore, shouldFail: false}

	m := coreauth.NewManager(store, nil, nil)
	m.SetConfig(cfg)
	m.RegisterExecutor(&syncTestExecutor{})
	s := &Service{cfg: cfg, coreManager: m}
	m.SetPoolRegistrySync(s.syncPoolRegistry)
	t.Cleanup(func() { registry.GetGlobalRegistry().UnregisterClient(a.ID) })

	// Register and promote
	a, err := m.Register(ctx, a)
	if err != nil {
		t.Fatal(err)
	}

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
	if err := s.syncPoolRegistry(ctx); err != nil {
		t.Fatal(err)
	}

	current, _ := m.GetByID(a.ID)
	if current.Disabled {
		t.Fatalf("Account should be enabled, got Disabled=%v", current.Disabled)
	}

	t.Logf("Initial state: Manager Disabled=%v, Registry models=%d",
		current.Disabled, len(registry.GetGlobalRegistry().GetModelsForClient(a.ID)))

	// === Test: Inject persist failure during disable ===
	store.shouldFail = true

	current.Disabled = true
	current.Status = coreauth.StatusDisabled

	_, errUpdate := m.Update(ctx, current)

	t.Logf("Update() result: error=%v", errUpdate)

	if errUpdate == nil {
		t.Errorf("❌ FAILED: Update() should return error")
	} else {
		t.Logf("✓ Update() returned error: %v", errUpdate)

		// Check Manager state
		managerAuth, _ := m.GetByID(a.ID)
		t.Logf("After rollback: Manager Disabled=%v", managerAuth.Disabled)

		if !managerAuth.Disabled {
			t.Errorf("failed disable must remain isolated, got Disabled=%v", managerAuth.Disabled)
		}
		preflight, errPreflight := m.PoolRequestPreflight(ctx, "gpt-5.6-luna", ex.Options{OriginalRequest: []byte(`{"model":"gpt-5.6-luna"}`)})
		if errPreflight == nil && preflight.EligibleCount != 0 {
			t.Errorf("scheduler/selector reopened failed disable: %+v %v", preflight, errPreflight)
		}
		if got := len(registry.GetGlobalRegistry().GetModelsForClient(a.ID)); got != 0 {
			t.Errorf("registry retained failed disable qualification: models=%d", got)
		}
	}

	// Commit a real disable, then verify a failed recovery cannot reopen it.
	store.shouldFail = false
	current, _ = m.GetByID(a.ID)
	current.Disabled = true
	current.Status = coreauth.StatusDisabled
	if _, errUpdate = m.Update(ctx, current); errUpdate != nil {
		t.Fatal(errUpdate)
	}
	if err := s.syncPoolRegistry(ctx); err != nil {
		t.Fatal(err)
	}
	store.shouldFail = true
	current, _ = m.GetByID(a.ID)
	current.Disabled = false
	current.Status = coreauth.StatusActive
	if _, errUpdate = m.Update(ctx, current); errUpdate == nil {
		t.Fatal("failed recovery unexpectedly succeeded")
	}
	managerAuth, _ := m.GetByID(a.ID)
	if !managerAuth.Disabled {
		t.Fatal("failed recovery reopened Manager state")
	}
	preflight, errPreflight := m.PoolRequestPreflight(ctx, "gpt-5.6-luna", ex.Options{OriginalRequest: []byte(`{"model":"gpt-5.6-luna"}`)})
	if errPreflight == nil && preflight.EligibleCount != 0 {
		t.Fatalf("failed recovery reopened dispatch: %+v", preflight)
	}
	if got := len(registry.GetGlobalRegistry().GetModelsForClient(a.ID)); got != 0 {
		t.Fatalf("failed recovery retained registry models: %d", got)
	}
}
