package cliproxy

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/watcher/synthesizer"
	filestore "github.com/router-for-me/CLIProxyAPI/v8/sdk/auth"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	ex "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
)

// Old admission fixtures must exercise the same explicit trust and capability
// commands as production, rather than treating an enabled file as authorization.
func pg02AdmitRegressionAuth(t *testing.T, m *coreauth.Manager, a *coreauth.Auth) *coreauth.Auth {
	t.Helper()
	identity := coreauth.PoolIdentityExpectation{AuthID: a.ID, Provider: a.Provider, CredentialDigest: coreauth.PoolCredentialDigest(a)}
	rev, states, err := m.PoolTrustSnapshot()
	if err != nil {
		t.Fatal(err)
	}
	for _, state := range states {
		if state.AuthID == a.ID {
			identity.Generation = state.Generation
		}
	}
	if err := m.PromotePoolIdentities(context.Background(), coreauth.PoolPromotion{ExpectedRevision: rev, Identities: []coreauth.PoolIdentityExpectation{identity}}); err != nil {
		t.Fatal(err)
	}
	rev, states, err = m.PoolTrustSnapshot()
	if err != nil {
		t.Fatal(err)
	}
	for _, state := range states {
		if state.AuthID == a.ID {
			identity.Generation = state.Generation
		}
	}
	if err := m.GrantPoolModelCapability(context.Background(), coreauth.PoolModelGrant{ExpectedRevision: rev, Identity: identity, Model: "gpt-5.6-luna"}); err != nil {
		t.Fatal(err)
	}
	current, ok := m.GetByID(a.ID)
	if !ok || current.Disabled {
		t.Fatal("explicit admission fixture did not enable account")
	}
	return current
}

func TestPG02ConvergenceDisabledLoadingContract(t *testing.T) {
	for _, role := range []string{"", "service"} {
		t.Run("role="+role, func(t *testing.T) {
			t.Setenv("CLEARAPI_POOL_ROLE", role)
			for _, tc := range []struct {
				name, raw string
				disabled  bool
			}{
				{"missing", `{"type":"codex"}`, role != ""},
				{"missing-with-management-false", `{"type":"codex","management_disabled":false}`, role != ""},
				{"false", `{"type":"codex","disabled":false}`, false},
				{"true", `{"type":"codex","disabled":true}`, true},
				{"null", `{"type":"codex","disabled":null,"management_disabled":false}`, true},
				{"string", `{"type":"codex","disabled":"false","management_disabled":false}`, true},
				{"management-true", `{"type":"codex","disabled":false,"management_disabled":true}`, true},
				{"management-invalid", `{"type":"codex","disabled":false,"management_disabled":null}`, true},
				{"wal-unknown", `{"type":"codex","disabled":false,"management_disabled":false,"management_recovery_state":"COMMITTED"}`, true},
			} {
				t.Run(tc.name, func(t *testing.T) {
					dir := t.TempDir()
					path := filepath.Join(dir, "synthetic.json")
					if err := os.WriteFile(path, []byte(tc.raw), 0600); err != nil {
						t.Fatal(err)
					}
					store := filestore.NewFileTokenStore()
					store.SetBaseDir(dir)
					loaded, err := store.List(context.Background())
					if err != nil || len(loaded) != 1 {
						t.Fatal("FileStore load", err)
					}
					watched, err := synthesizer.SynthesizeAuthFile(&synthesizer.SynthesisContext{AuthDir: dir, Now: time.Now()}, path, []byte(tc.raw))
					if err != nil || len(watched) != 1 {
						t.Fatal("watcher load", err)
					}
					for _, a := range []*coreauth.Auth{loaded[0], watched[0]} {
						if a.Disabled != tc.disabled || coreauth.ManagementIsolation(a) != tc.disabled {
							t.Fatalf("load contract: disabled=%t isolated=%t want=%t", a.Disabled, coreauth.ManagementIsolation(a), tc.disabled)
						}
					}
					data, err := os.ReadFile(path)
					if err != nil || !bytes.Equal(data, []byte(tc.raw)) {
						t.Fatal("read path rewrote persistent state", err)
					}
				})
			}
		})
	}
}

func TestPG02ConvergenceUnknownPoolStateCannotReuseTrust(t *testing.T) {
	f := newPG02CommitFixture(t)
	f.check(t, f.m, false)
	stale, _ := f.m.GetByID(f.id)
	raw, err := os.ReadFile(f.path)
	if err != nil {
		t.Fatal(err)
	}
	var metadata map[string]any
	if err := json.Unmarshal(raw, &metadata); err != nil {
		t.Fatal(err)
	}
	delete(metadata, "disabled")
	metadata[coreauth.ManagementDisabledKey] = false
	raw, err = json.Marshal(metadata)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(f.path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if err := f.m.Load(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := f.s.syncPoolRegistry(context.Background()); err != nil {
		t.Fatal(err)
	}
	f.check(t, f.m, true)
	if f.m.PublishPoolModels(stale, stale.Provider, []*registry.ModelInfo{{ID: "gpt-5.6-luna"}}) {
		t.Fatal("stale enabled snapshot republished unknown pool state")
	}
	command := pg02IsolationCommand(t, f)
	if err := f.m.PromotePoolIdentities(context.Background(), command); err != nil {
		t.Fatal(err)
	}
	command = pg02IsolationCommand(t, f)
	if err := f.m.GrantPoolModelCapability(context.Background(), coreauth.PoolModelGrant{ExpectedRevision: command.ExpectedRevision, Identity: command.Identities[0], Model: "gpt-5.6-luna"}); err != nil {
		t.Fatal(err)
	}
	f.check(t, f.m, true)
	f.restart(t, true)
}

// This is the lawful serialization observed in the original concurrency race.
// A successful explicit recovery must have a verified COMMITTED WAL; a later
// promotion still invalidates the old capability and publication generation.
func TestPG02ConvergenceAuthorizedRecoveryBeforePromotion(t *testing.T) {
	f := newPG02CommitFixture(t)
	if response := f.patch(true); response.Code != http.StatusOK {
		t.Fatalf("disable: %d %s", response.Code, response.Body.String())
	}
	if response := f.patch(false); response.Code != http.StatusOK {
		t.Fatalf("authorized recovery: %d %s", response.Code, response.Body.String())
	}
	f.check(t, f.m, false)
	loaded, err := f.store.List(context.Background())
	if err != nil || len(loaded) != 1 {
		t.Fatal("recovered disk identity unavailable", err)
	}
	a := loaded[0]
	opID, _ := a.Metadata[coreauth.RecoveryOpIDKey].(string)
	revision, _ := a.Metadata[coreauth.RecoveryRevisionKey].(float64)
	op := coreauth.ManagementRecoveryOperation{OpID: opID, AuthID: a.ID, CredentialDigest: coreauth.PoolCredentialDigest(a), Generation: a.Generation, Revision: uint64(revision), State: coreauth.ManagementRecoveryPrepared}
	state, err := f.store.VerifyManagementRecovery(context.Background(), a, op)
	if err != nil || state != coreauth.ManagementRecoveryCommitted {
		t.Fatal("200 recovery lacked verified COMMITTED WAL", state, err)
	}
	stale, _ := f.m.GetByID(f.id)
	command := pg02IsolationCommand(t, f)
	if err := f.m.PromotePoolIdentities(context.Background(), command); err != nil {
		t.Fatal(err)
	}
	if f.m.PublishPoolModels(stale, stale.Provider, []*registry.ModelInfo{{ID: "gpt-5.6-luna"}}) {
		t.Fatal("old auth generation republished after promotion")
	}
	if err := f.m.GrantPoolModelCapability(context.Background(), coreauth.PoolModelGrant{ExpectedRevision: command.ExpectedRevision, Identity: command.Identities[0], Model: "gpt-5.6-luna"}); err == nil {
		t.Fatal("old revision and trust generation granted capability")
	}
	preflight, err := f.m.PoolRequestPreflight(context.Background(), "gpt-5.6-luna", ex.Options{})
	if err != nil || preflight.EligibleCount != 0 || len(f.m.PoolModelProviders("gpt-5.6-luna")) != 0 || len(registry.GetGlobalRegistry().GetModelsForClient(f.id)) != 0 {
		t.Fatal("promotion reused old capability", preflight, err)
	}
	if response := f.patch(true); response.Code != http.StatusOK {
		t.Fatalf("final disable: %d %s", response.Code, response.Body.String())
	}
	f.check(t, f.m, true)
	f.restart(t, true)
}
