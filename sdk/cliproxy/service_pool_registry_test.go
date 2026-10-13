package cliproxy

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	ex "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/config"
)

// Real service publication and watcher path; synthetic identity, no provider call.
func TestPoolServiceRegistryWatcherParity(t *testing.T) {
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
	a := &coreauth.Auth{ID: "synthetic-service-auth", Provider: "codex", FileName: "synthetic-service-auth.json", Status: coreauth.StatusActive, Attributes: map[string]string{coreauth.AttributeAuthKind: coreauth.AuthKindOAuth, "plan_type": "pro"}, Metadata: map[string]any{"access_token": "synthetic-unused", "account_id": "synthetic-account", "email": "fixture@staging.invalid"}}
	record := coreauth.PoolGrantFile{GuardVersion: coreauth.PoolGuardVersion, Revision: 1, ExecutorID: "synthetic-service", Grants: []coreauth.PoolGrant{{AuthID: a.ID, Provider: a.Provider, CredentialDigest: coreauth.PoolCredentialDigest(a), Models: []string{"gpt-5.6-luna"}, Capabilities: []string{"text_chat", "stream_text", "exact_usage"}, Enabled: true, MaxConcurrency: 1, ExpiresAt: time.Now().Add(25 * time.Minute).Unix(), SourceEvidence: []string{"synthetic-source"}, TestEvidence: []string{"synthetic-test"}}}}
	body, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(grants, body, 0600); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{AuthDir: dir}
	m := coreauth.NewManager(nil, nil, nil)
	m.SetConfig(cfg)
	m.RegisterExecutor(&syncTestExecutor{})
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
				return rev, coreauth.PoolIdentityExpectation{AuthID: a.ID, Provider: a.Provider, CredentialDigest: coreauth.PoolCredentialDigest(a), Generation: st.Generation}
			}
		}
		return rev, coreauth.PoolIdentityExpectation{AuthID: a.ID, Provider: a.Provider, CredentialDigest: coreauth.PoolCredentialDigest(a)}
	}
	rev, identity := expectation()
	if err = m.PromotePoolIdentities(ctx, coreauth.PoolPromotion{ExpectedRevision: rev, Identities: []coreauth.PoolIdentityExpectation{identity}}); err != nil {
		t.Fatal(err)
	}
	rev, identity = expectation()
	if err = m.GrantPoolModelCapability(ctx, coreauth.PoolModelGrant{ExpectedRevision: rev, Identity: identity, Model: "gpt-5.6-luna"}); err != nil {
		t.Fatal(err)
	}
	assertParity := func() {
		p, e := m.PoolRequestPreflight(ctx, "gpt-5.6-luna", ex.Options{OriginalRequest: []byte(`{"model":"gpt-5.6-luna","tools":[]}`)})
		if e != nil || p.EligibleCount != 1 || len(m.PoolModelProviders("gpt-5.6-luna")) != 1 {
			t.Fatalf("parity lost: %+v %v", p, e)
		}
		models := registry.GetGlobalRegistry().GetModelsForClient(a.ID)
		if len(models) != 1 || models[0].ID != "gpt-5.6-luna" {
			t.Fatal("capability expanded")
		}
	}
	assertParity()
	current, _ := m.GetByID(a.ID)
	old := current.Clone()
	s.applyCoreAuthAddOrUpdate(ctx, current.Clone())
	assertParity()
	// An old watcher snapshot cannot overwrite the newly published generation.
	s.registerModelsForAuth(ctx, old)
	assertParity()
	old.Disabled = true
	s.registerModelsForAuth(ctx, old)
	assertParity()
	current, _ = m.GetByID(a.ID)
	epoch := registry.GetGlobalRegistry().ClientRegistrationEpoch(a.ID)
	s.registerModelsForAuth(ctx, current)
	s.registerModelsForAuth(ctx, current)
	if registry.GetGlobalRegistry().ClientRegistrationEpoch(a.ID) != epoch {
		t.Fatal("duplicate event rebuilt registry")
	}
}
