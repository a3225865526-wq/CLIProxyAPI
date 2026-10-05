package auth

import (
	"context"
	"errors"
	"os"
	"sync"
	"testing"
	"time"

	internalconfig "github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
)

// poolStage3Probe records which account executed and supports gated dispatch so
// revoke races can be staged deterministically.
type poolStage3Probe struct {
	poolProbeExecutor
	mu       sync.Mutex
	executed []string
	permit   chan struct{}
	sent     chan struct{}
	finished chan struct{}
	complete chan struct{}
}

func (probe *poolStage3Probe) Execute(ctx context.Context, auth *Auth, _ cliproxyexecutor.Request, _ cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
	if probe.permit != nil {
		<-probe.permit
	}
	if err := cliproxyexecutor.BeforeUpstreamDispatch(ctx); err != nil {
		return cliproxyexecutor.Response{}, err
	}
	probe.mu.Lock()
	probe.executed = append(probe.executed, auth.ID)
	probe.mu.Unlock()
	probe.calls.Add(1)
	if probe.sent != nil {
		select {
		case probe.sent <- struct{}{}:
		default:
		}
	}
	select {
	case <-ctx.Done():
		return cliproxyexecutor.Response{}, ctx.Err()
	case <-probe.complete:
		return cliproxyexecutor.Response{}, nil
	}
}

func (probe *poolStage3Probe) executedBy() []string {
	probe.mu.Lock()
	defer probe.mu.Unlock()
	return append([]string(nil), probe.executed...)
}

func poolRequestModel(m *Manager, model string) error {
	_, err := m.Execute(context.Background(), []string{"codex"}, cliproxyexecutor.Request{Model: model}, cliproxyexecutor.Options{})
	return err
}

// poolStage3Identity reads the current policy revision and the identity's trust
// generation for a stale-write-protected capability command.
func poolStage3Identity(t *testing.T, m *Manager, auth *Auth) (uint64, PoolIdentityExpectation) {
	t.Helper()
	revision, states, err := m.PoolTrustSnapshot()
	if err != nil {
		t.Fatal(err)
	}
	identity := PoolIdentityExpectation{AuthID: auth.ID, Provider: auth.Provider, CredentialDigest: PoolCredentialDigest(auth)}
	for _, state := range states {
		if state.AuthID == auth.ID {
			identity.Generation = state.Generation
		}
	}
	return revision, identity
}

// poolStage3AddAccount adds a second synthetic pool account with its own grant
// floor, batch-promotes it together with the fixture identity, and grants the
// requested model capabilities. Order matters: the floor file must contain the
// new grant before registration, and promotion demotes every trusted snapshot,
// so both identities are promoted in one batch.
func poolStage3AddAccount(t *testing.T, m *Manager, file string, record *PoolGrantFile, id string, models []string, prepare func(*Auth)) *Auth {
	t.Helper()
	auth := &Auth{ID: id, Provider: "codex", FileName: id + ".json", Status: StatusActive, Attributes: map[string]string{AttributeAuthKind: AuthKindOAuth}, Metadata: map[string]any{"access_token": "synthetic-" + id}}
	if prepare != nil {
		prepare(auth)
	}
	grant := record.Grants[0]
	grant.AuthID = id
	grant.CredentialDigest = PoolCredentialDigest(auth)
	grant.Models = append([]string(nil), models...)
	record.Grants = append(record.Grants, grant)
	record.Revision++
	writePoolGrant(t, file, *record)
	registered, err := m.Register(context.Background(), auth)
	if err != nil {
		t.Fatal(err)
	}
	registry.GetGlobalRegistry().RegisterClient(id, "codex", []*registry.ModelInfo{{ID: models[0]}})
	t.Cleanup(func() { registry.GetGlobalRegistry().UnregisterClient(id) })
	previousRevision, previousCapabilities, err := m.PoolModelSnapshot()
	if err != nil {
		t.Fatal(err)
	}
	_ = previousRevision
	revision, states, err := m.PoolTrustSnapshot()
	if err != nil {
		t.Fatal(err)
	}
	identities := make([]PoolIdentityExpectation, 0, len(states)+1)
	for _, state := range states {
		if state.State == PoolTrustPending || state.State == PoolTrustTrusted {
			identities = append(identities, PoolIdentityExpectation{AuthID: state.AuthID, Provider: state.Provider, CredentialDigest: state.CredentialDigest, Generation: state.Generation})
		}
	}
	identities = append(identities, PoolIdentityExpectation{AuthID: id, Provider: "codex", CredentialDigest: PoolCredentialDigest(auth)})
	if err := m.PromotePoolIdentities(context.Background(), PoolPromotion{ExpectedRevision: revision, Identities: identities}); err != nil {
		t.Fatal(err)
	}
	// The new trust generation invalidates old-generation capability records by
	// design, so every previously admitted model needs an explicit re-grant.
	for _, item := range previousCapabilities {
		if item.State != PoolCapabilityVerified {
			continue
		}
		holder, ok := m.GetByID(item.AuthID)
		if !ok || holder == nil {
			t.Fatal("capability holder vanished")
		}
		if err := grantPoolModelCapability(t, m, holder, item.Model); err != nil {
			t.Fatal(err)
		}
	}
	for _, model := range models {
		if err := grantPoolModelCapability(t, m, registered, model); err != nil {
			t.Fatal(err)
		}
	}
	return registered
}

func TestPoolStage3DefaultDenial(t *testing.T) {
	t.Run("trusted-unknown-model", func(t *testing.T) {
		m, probe, _, _, _ := poolGuardFixture(t, "service")
		for _, model := range []string{"synthetic-unknown", "synthetic-native-x", "x-synthetic-native", "synthetic-nativ", "SYNTHETIC-NATIVE"} {
			if err := poolRequestModel(m, model); err == nil || probe.calls.Load() != 0 {
				t.Fatalf("unadmitted model %q executed", model)
			}
		}
	})
	t.Run("trusted-unverified-capability", func(t *testing.T) {
		m, probe, auth, file, record := poolGuardFixture(t, "service")
		// Extend the operator floor to a second model, re-promote, and re-grant
		// only the original model: the floor alone must not admit anything.
		record.Grants[0].Models = append(record.Grants[0].Models, "synthetic-other")
		record.Revision++
		writePoolGrant(t, file, record)
		explicitPoolPromotion(t, m)
		if err := poolRequestModel(m, "synthetic-native"); err != nil || probe.calls.Load() != 1 {
			t.Fatal("granted model denied after re-promotion", err)
		}
		if err := poolRequestModel(m, "synthetic-other"); err == nil || probe.calls.Load() != 1 {
			t.Fatal("floor model without capability executed")
		}
		_ = auth
	})
	t.Run("untrusted-allowed-model", func(t *testing.T) {
		m, probe, _, file, record := poolGuardFixture(t, "service")
		record.Revision++
		writePoolGrant(t, file, record)
		if err := poolRequestModel(m, "synthetic-native"); err == nil || probe.calls.Load() != 0 {
			t.Fatal("pending account served an admitted model")
		}
	})
	t.Run("revoked-allowed-model", func(t *testing.T) {
		m, probe, _, _, _ := poolGuardFixture(t, "service")
		poolRevoke(t, m)
		if err := poolRequestModel(m, "synthetic-native"); err == nil || probe.calls.Load() != 0 {
			t.Fatal("revoked account served an admitted model")
		}
	})
}

func TestPoolStage3GrantLifecycle(t *testing.T) {
	t.Run("valid-grant", func(t *testing.T) {
		m, _, auth, _, _ := poolGuardFixture(t, "service")
		revision, capabilities, err := m.PoolModelSnapshot()
		if err != nil {
			t.Fatal(err)
		}
		if len(capabilities) != 1 || capabilities[0].State != PoolCapabilityVerified || capabilities[0].Model != "synthetic-native" {
			t.Fatal("fixture capability missing", capabilities)
		}
		_, identity := poolStage3Identity(t, m, auth)
		if capabilities[0].Generation != identity.Generation {
			t.Fatalf("capability generation %d does not bind trust generation %d", capabilities[0].Generation, identity.Generation)
		}
		if revision < 3 {
			t.Fatal("capability grant did not advance the shared revision", revision)
		}
	})
	t.Run("persistence-failure", func(t *testing.T) {
		m, probe, auth, _, _ := poolGuardFixture(t, "service")
		revision, identity := poolStage3Identity(t, m, auth)
		file, err := os.OpenFile(m.poolGuard.checkpoint, os.O_RDWR, 0)
		if err != nil {
			t.Fatal(err)
		}
		if err := lockPoolCheckpoint(file); err != nil {
			t.Fatal(err)
		}
		grantErr := m.GrantPoolModelCapability(context.Background(), PoolModelGrant{ExpectedRevision: revision, Identity: identity, Model: "synthetic-other"})
		unlockPoolCheckpoint(file)
		file.Close()
		if grantErr == nil {
			t.Fatal("failed persistence reported grant success")
		}
		next, capabilities, err := m.PoolModelSnapshot()
		if err != nil || next != revision || len(capabilities) != 1 {
			t.Fatal("failed grant changed committed state", err, capabilities)
		}
		if err := poolRequestModel(m, "synthetic-native"); err != nil || probe.calls.Load() != 1 {
			t.Fatal("failed grant disturbed committed authority", err)
		}
	})
	t.Run("stale-identity", func(t *testing.T) {
		m, _, auth, _, _ := poolGuardFixture(t, "service")
		revision, identity := poolStage3Identity(t, m, auth)
		identity.CredentialDigest = "different"
		if err := m.GrantPoolModelCapability(context.Background(), PoolModelGrant{ExpectedRevision: revision, Identity: identity, Model: "synthetic-other"}); err == nil {
			t.Fatal("stale identity grant accepted")
		}
	})
	t.Run("stale-generation", func(t *testing.T) {
		m, _, auth, _, _ := poolGuardFixture(t, "service")
		revision, identity := poolStage3Identity(t, m, auth)
		identity.Generation--
		if err := m.GrantPoolModelCapability(context.Background(), PoolModelGrant{ExpectedRevision: revision, Identity: identity, Model: "synthetic-other"}); err == nil {
			t.Fatal("stale generation grant accepted")
		}
	})
	t.Run("duplicate-grant", func(t *testing.T) {
		m, probe, auth, _, _ := poolGuardFixture(t, "service")
		before, _, err := m.PoolModelSnapshot()
		if err != nil {
			t.Fatal(err)
		}
		if err := grantPoolModelCapability(t, m, auth, "synthetic-native"); err != nil {
			t.Fatal(err)
		}
		after, capabilities, err := m.PoolModelSnapshot()
		if err != nil || len(capabilities) != 1 || capabilities[0].State != PoolCapabilityVerified {
			t.Fatal("duplicate grant split state", err, capabilities)
		}
		if after != before+1 {
			t.Fatal("duplicate grant did not deterministically advance one revision", before, after)
		}
		if err := poolRequestModel(m, "synthetic-native"); err != nil || probe.calls.Load() != 1 {
			t.Fatal("duplicate grant broke admission", err)
		}
	})
	t.Run("concurrent-grant-revoke", func(t *testing.T) {
		m, _, auth, _, _ := poolGuardFixture(t, "service")
		revision, identity := poolStage3Identity(t, m, auth)
		start := make(chan struct{})
		var group sync.WaitGroup
		group.Go(func() {
			<-start
			_ = m.GrantPoolModelCapability(context.Background(), PoolModelGrant{ExpectedRevision: revision, Identity: identity, Model: "synthetic-native"})
		})
		group.Go(func() {
			<-start
			_ = m.RevokePoolModelCapability(context.Background(), PoolModelRevoke{ExpectedRevision: revision, Identity: identity, Model: "synthetic-native"})
		})
		close(start)
		group.Wait()
		_, capabilities, err := m.PoolModelSnapshot()
		if err != nil || len(capabilities) != 1 {
			t.Fatal("concurrent capability commands corrupted the ledger", err, capabilities)
		}
		err = poolRequestModel(m, "synthetic-native")
		if capabilities[0].State == PoolCapabilityRevoked && err == nil {
			t.Fatal("revoked model still served")
		}
		if capabilities[0].State == PoolCapabilityVerified && err != nil {
			t.Fatal("verified model denied after race", err)
		}
	})
}

func TestPoolStage3ModelMatching(t *testing.T) {
	t.Run("exact-match", func(t *testing.T) {
		m, probe, _, _, _ := poolGuardFixture(t, "service")
		if err := poolRequestModel(m, "synthetic-native"); err != nil || probe.calls.Load() != 1 {
			t.Fatal("exact admitted model denied", err)
		}
	})
	t.Run("alias-resolves-to-canonical", func(t *testing.T) {
		m, _, _, file, record := poolGuardFixture(t, "service")
		probe := &poolStage3Probe{complete: make(chan struct{})}
		close(probe.complete)
		m.RegisterExecutor(probe)
		aliased := poolStage3AddAccount(t, m, file, &record, "synthetic-aliased", []string{"synthetic-native"}, func(auth *Auth) {
			SetOAuthModelAliasesAttribute(auth, []internalconfig.OAuthModelAlias{{Name: "synthetic-native", Alias: "alias-native"}})
		})
		if err := poolRequestModel(m, "alias-native"); err != nil || probe.calls.Load() != 1 {
			t.Fatal("alias to an admitted canonical model denied", err)
		}
		if executed := probe.executedBy(); len(executed) != 1 || executed[0] != aliased.ID {
			t.Fatalf("alias request executed on %v", probe.executedBy())
		}
	})
	t.Run("case-not-normalized", func(t *testing.T) {
		m, probe, _, _, _ := poolGuardFixture(t, "service")
		// The project canonical key does not case-fold: the admitted lowercase
		// model does not authorize its uppercase variant, and an uppercase grant
		// alone does not admit the lowercase model.
		if err := poolRequestModel(m, "SYNTHETIC-NATIVE"); err == nil || probe.calls.Load() != 0 {
			t.Fatal("uppercase variant executed")
		}
		auth, ok := m.GetByID("synthetic-pool-account")
		if !ok {
			t.Fatal("fixture account vanished")
		}
		if err := grantPoolModelCapability(t, m, auth, "SYNTHETIC-NATIVE"); err != nil {
			t.Fatal(err)
		}
		if err := poolRequestModel(m, "SYNTHETIC-NATIVE"); err == nil || probe.calls.Load() != 0 {
			t.Fatal("uppercase capability executed without a floor entry")
		}
	})
	t.Run("unknown-alias-fail-closed", func(t *testing.T) {
		m, _, _, file, record := poolGuardFixture(t, "service")
		probe := &poolStage3Probe{complete: make(chan struct{})}
		close(probe.complete)
		m.RegisterExecutor(probe)
		poolStage3AddAccount(t, m, file, &record, "synthetic-aliased", []string{"synthetic-native"}, func(auth *Auth) {
			SetOAuthModelAliasesAttribute(auth, []internalconfig.OAuthModelAlias{{Name: "synthetic-native", Alias: "alias-native"}})
		})
		if err := poolRequestModel(m, "alias-unknown"); err == nil || probe.calls.Load() != 0 {
			t.Fatal("unknown alias executed")
		}
	})
	t.Run("mapping-cycle", func(t *testing.T) {
		m, _, _, file, record := poolGuardFixture(t, "service")
		probe := &poolStage3Probe{complete: make(chan struct{})}
		close(probe.complete)
		m.RegisterExecutor(probe)
		aliased := poolStage3AddAccount(t, m, file, &record, "synthetic-aliased", []string{"synthetic-native"}, func(auth *Auth) {
			SetOAuthModelAliasesAttribute(auth, []internalconfig.OAuthModelAlias{
				{Name: "cycle-b", Alias: "cycle-a"},
				{Name: "cycle-a", Alias: "cycle-b"},
			})
		})
		_ = aliased
		// Alias resolution is single-step: cycle-a resolves to cycle-b and stops.
		// cycle-b has no capability, so the request fails closed without looping.
		if err := poolRequestModel(m, "cycle-a"); err == nil || probe.calls.Load() != 0 {
			t.Fatal("alias cycle executed or looped")
		}
	})
}

func TestPoolStage3RouterFiltering(t *testing.T) {
	t.Run("only-admitted-account-selected", func(t *testing.T) {
		m, _, _, file, record := poolGuardFixture(t, "service")
		probe := &poolStage3Probe{complete: make(chan struct{})}
		close(probe.complete)
		m.RegisterExecutor(probe)
		poolStage3AddAccount(t, m, file, &record, "synthetic-second", []string{"synthetic-other"}, nil)
		if err := poolRequestModel(m, "synthetic-native"); err != nil {
			t.Fatal(err)
		}
		if executed := probe.executedBy(); len(executed) != 1 || executed[0] != "synthetic-pool-account" {
			t.Fatalf("model-native executed on %v", probe.executedBy())
		}
		if err := poolRequestModel(m, "synthetic-other"); err != nil {
			t.Fatal(err)
		}
		if executed := probe.executedBy(); len(executed) != 2 || executed[1] != "synthetic-second" {
			t.Fatalf("model-other executed on %v", probe.executedBy())
		}
	})
	t.Run("unhealthy-account-no-unadmitted-fallback", func(t *testing.T) {
		m, _, auth, file, record := poolGuardFixture(t, "service")
		probe := &poolStage3Probe{complete: make(chan struct{})}
		close(probe.complete)
		m.RegisterExecutor(probe)
		poolStage3AddAccount(t, m, file, &record, "synthetic-second", []string{"synthetic-other"}, nil)
		cooled := auth.Clone()
		cooled.ModelStates = map[string]*ModelState{"synthetic-native": {Unavailable: true, NextRetryAfter: time.Now().Add(time.Hour)}}
		if _, err := m.Update(context.Background(), cooled); err != nil {
			t.Fatal(err)
		}
		if err := poolRequestModel(m, "synthetic-native"); err == nil {
			t.Fatal("cooled model served")
		}
		if executed := probe.executedBy(); len(executed) != 0 {
			t.Fatalf("unadmitted fallback executed on %v", probe.executedBy())
		}
	})
	t.Run("fallback-rechecks-capability", func(t *testing.T) {
		m, _, _, file, record := poolGuardFixture(t, "service")
		poolStage3AddAccount(t, m, file, &record, "synthetic-second", []string{"synthetic-native"}, nil)
		second, _ := m.GetByID("synthetic-second")
		if err := revokePoolModelCapability(t, m, second, "synthetic-native"); err != nil {
			t.Fatal(err)
		}
		m.SetRetryConfig(3, 0, 3)
		failing := &poolPreDispatchFailure{}
		m.RegisterExecutor(failing)
		// The first attempt fails pre-dispatch; the fallback account is trusted
		// but no longer admitted for the model, so the retry must not use it.
		if err := poolRequestModel(m, "synthetic-native"); err == nil || failing.calls.Load() != 0 {
			t.Fatal("fallback skipped the capability filter", err)
		}
		// An explicit grant is the only way the fallback account becomes usable.
		if err := grantPoolModelCapability(t, m, second, "synthetic-native"); err != nil {
			t.Fatal(err)
		}
		if err := poolRequestModel(m, "synthetic-native"); err != nil || failing.calls.Load() != 1 {
			t.Fatal("explicitly granted fallback denied", err)
		}
	})
	t.Run("no-eligible-account", func(t *testing.T) {
		m, probe, auth, _, _ := poolGuardFixture(t, "service")
		if err := revokePoolModelCapability(t, m, auth, "synthetic-native"); err != nil {
			t.Fatal(err)
		}
		err := poolRequestModel(m, "synthetic-native")
		var authErr *Error
		if !errors.As(err, &authErr) || authErr.Code != "pool_no_eligible_account" {
			t.Fatalf("expected pool_no_eligible_account, got %v", err)
		}
		if probe.calls.Load() != 0 {
			t.Fatal("no-eligible request reached upstream")
		}
	})
}

// poolStage3MultiModelFixture extends the operator floor to a second model,
// re-promotes, and grants both models so single-model revoke semantics are
// observable while the other model keeps serving.
func poolStage3MultiModelFixture(t *testing.T) (*Manager, *poolProbeExecutor, *Auth) {
	t.Helper()
	m, probe, auth, file, record := poolGuardFixture(t, "service")
	record.Grants[0].Models = append(record.Grants[0].Models, "synthetic-other")
	record.Revision++
	writePoolGrant(t, file, record)
	explicitPoolPromotion(t, m)
	if err := grantPoolModelCapability(t, m, auth, "synthetic-other"); err != nil {
		t.Fatal(err)
	}
	return m, probe, auth
}

func TestPoolStage3ModelRevoke(t *testing.T) {
	t.Run("revoke-blocks-only-revoked-model", func(t *testing.T) {
		m, probe, auth := poolStage3MultiModelFixture(t)
		if err := revokePoolModelCapability(t, m, auth, "synthetic-native"); err != nil {
			t.Fatal(err)
		}
		if err := poolRequestModel(m, "synthetic-native"); err == nil || probe.calls.Load() != 0 {
			t.Fatal("revoked model still served")
		}
		if err := poolRequestModel(m, "synthetic-other"); err != nil || probe.calls.Load() != 1 {
			t.Fatal("other admitted model disturbed by revoke", err)
		}
	})
	t.Run("health-does-not-restore", func(t *testing.T) {
		m, probe, auth := poolStage3MultiModelFixture(t)
		if err := revokePoolModelCapability(t, m, auth, "synthetic-native"); err != nil {
			t.Fatal(err)
		}
		m.MarkResult(context.Background(), Result{AuthID: auth.ID, Provider: auth.Provider, Model: "synthetic-native", RouteModel: "synthetic-native", Success: true})
		if err := poolRequestModel(m, "synthetic-native"); err == nil || probe.calls.Load() != 0 {
			t.Fatal("health success restored a revoked model")
		}
	})
	t.Run("reload-does-not-restore", func(t *testing.T) {
		m, probe, auth := poolStage3MultiModelFixture(t)
		if err := revokePoolModelCapability(t, m, auth, "synthetic-native"); err != nil {
			t.Fatal(err)
		}
		if _, err := m.Register(context.Background(), auth); err != nil {
			t.Fatal(err)
		}
		if err := poolRequestModel(m, "synthetic-native"); err == nil || probe.calls.Load() != 0 {
			t.Fatal("reload restored a revoked model")
		}
	})
	t.Run("restart-does-not-restore", func(t *testing.T) {
		m, probe, auth := poolStage3MultiModelFixture(t)
		if err := revokePoolModelCapability(t, m, auth, "synthetic-native"); err != nil {
			t.Fatal(err)
		}
		restarted := NewManager(nil, nil, nil)
		restarted.SetConfig(m.runtimeConfigSnapshot())
		restarted.RegisterExecutor(probe)
		if _, err := restarted.Register(context.Background(), auth); err != nil {
			t.Fatal(err)
		}
		if err := poolRequestModel(restarted, "synthetic-native"); err == nil || probe.calls.Load() != 0 {
			t.Fatal("restart restored a revoked model")
		}
		_, capabilities, err := restarted.PoolModelSnapshot()
		if err != nil || len(capabilities) != 2 {
			t.Fatal("capability ledger lost on restart", err, capabilities)
		}
		for _, item := range capabilities {
			if item.Model == "synthetic-native" && item.State != PoolCapabilityRevoked {
				t.Fatal("revoked state mutated on restart", item)
			}
		}
	})
	t.Run("stale-grant-does-not-restore", func(t *testing.T) {
		m, probe, auth := poolStage3MultiModelFixture(t)
		staleRevision, staleIdentity := poolStage3Identity(t, m, auth)
		if err := revokePoolModelCapability(t, m, auth, "synthetic-native"); err != nil {
			t.Fatal(err)
		}
		staleIdentity.CredentialDigest = PoolCredentialDigest(auth)
		if err := m.GrantPoolModelCapability(context.Background(), PoolModelGrant{ExpectedRevision: staleRevision, Identity: staleIdentity, Model: "synthetic-native"}); err == nil {
			t.Fatal("stale grant command restored a revoked model")
		}
		if err := poolRequestModel(m, "synthetic-native"); err == nil || probe.calls.Load() != 0 {
			t.Fatal("stale grant restored a revoked model")
		}
	})
}

func TestPoolStage3DispatchRace(t *testing.T) {
	t.Run("pre-dispatch-model-revoke-blocks-upstream", func(t *testing.T) {
		m, _, auth, _, _ := poolGuardFixture(t, "service")
		probe := &poolStage3Probe{permit: make(chan struct{}), complete: make(chan struct{})}
		m.RegisterExecutor(probe)
		result := make(chan error, 1)
		go func() {
			result <- poolRequestModel(m, "synthetic-native")
		}()
		// The probe blocks on its permit before the dispatch fence; revoking the
		// model here must make the fence refuse the upstream call.
		deadline := time.Now().Add(3 * time.Second)
		for len(m.PoolInFlightSnapshot()) == 0 {
			if time.Now().After(deadline) {
				t.Fatal("lease was never acquired")
			}
			time.Sleep(time.Millisecond)
		}
		if err := revokePoolModelCapability(t, m, auth, "synthetic-native"); err != nil {
			t.Fatal(err)
		}
		close(probe.permit)
		select {
		case err := <-result:
			if err == nil {
				t.Fatal("revoked model dispatched")
			}
		case <-time.After(3 * time.Second):
			t.Fatal("request did not terminate")
		}
		if probe.calls.Load() != 0 {
			t.Fatal("upstream received a revoked-model call")
		}
		if len(m.PoolInFlightSnapshot()) != 0 {
			t.Fatal("lease leaked")
		}
	})
	t.Run("post-dispatch-model-revoke-no-replay", func(t *testing.T) {
		m, _, auth, _, _ := poolGuardFixture(t, "service")
		probe := &poolStage3Probe{sent: make(chan struct{}, 1), complete: make(chan struct{})}
		m.RegisterExecutor(probe)
		result := make(chan error, 1)
		go func() {
			result <- poolRequestModel(m, "synthetic-native")
		}()
		select {
		case <-probe.sent:
		case <-time.After(3 * time.Second):
			t.Fatal("probe never dispatched")
		}
		if err := revokePoolModelCapability(t, m, auth, "synthetic-native"); err != nil {
			t.Fatal(err)
		}
		close(probe.complete)
		select {
		case err := <-result:
			if err == nil {
				t.Fatal("revoked dispatch reported success")
			}
		case <-time.After(3 * time.Second):
			t.Fatal("request did not terminate")
		}
		if probe.calls.Load() != 1 {
			t.Fatalf("revoked dispatch replayed: %d calls", probe.calls.Load())
		}
		if len(m.PoolInFlightSnapshot()) != 0 {
			t.Fatal("lease leaked")
		}
	})
	t.Run("lease-authorize-after-model-revoke", func(t *testing.T) {
		m, _, auth, _, _ := poolGuardFixture(t, "service")
		wrapped, _ := m.Executor("codex")
		ctx, _ := m.poolExecutionContext(context.Background())
		lease, err := wrapped.(*poolExecutor).begin(ctx, auth, cliproxyexecutor.Request{Model: "synthetic-native"}, cliproxyexecutor.Options{}, false, true)
		if err != nil {
			t.Fatal(err)
		}
		if err := revokePoolModelCapability(t, m, auth, "synthetic-native"); err != nil {
			t.Fatal(err)
		}
		if err := lease.AuthorizeDispatch(); err == nil {
			t.Fatal("stale lease dispatched a revoked model")
		}
		lease.End("rejected")
		if len(m.PoolInFlightSnapshot()) != 0 {
			t.Fatal("lease leaked")
		}
	})
	t.Run("account-revoke-and-model-revoke", func(t *testing.T) {
		m, probe, auth, _, _ := poolGuardFixture(t, "service")
		revision, identity := poolStage3Identity(t, m, auth)
		start := make(chan struct{})
		var group sync.WaitGroup
		group.Go(func() {
			<-start
			_ = m.RevokePoolIdentity(context.Background(), PoolRevocation{ExpectedRevision: revision, Identity: identity})
		})
		group.Go(func() {
			<-start
			_ = m.RevokePoolModelCapability(context.Background(), PoolModelRevoke{ExpectedRevision: revision, Identity: identity, Model: "synthetic-native"})
		})
		close(start)
		group.Wait()
		if err := poolRequestModel(m, "synthetic-native"); err == nil || probe.calls.Load() != 0 {
			t.Fatal("concurrent revocations reopened the model")
		}
		_, states, err := m.PoolTrustSnapshot()
		if err != nil || len(states) != 1 {
			t.Fatal("trust state inconsistent after concurrent revocations", err, states)
		}
		if states[0].State == PoolTrustTrusted {
			// The model revoke won the revision race and the account revoke lost
			// its CAS; the model must then be revoked for the account to serve.
			_, capabilities, err := m.PoolModelSnapshot()
			if err != nil {
				t.Fatal(err)
			}
			for _, item := range capabilities {
				if item.Model == "synthetic-native" && item.State != PoolCapabilityRevoked {
					t.Fatal("raced revocation left the model admitted", item)
				}
			}
			// A fresh security revoke must then win, per the CAS contract.
			poolRevoke(t, m)
			if err := poolRequestModel(m, "synthetic-native"); err == nil || probe.calls.Load() != 0 {
				t.Fatal("fresh account revoke did not close the model")
			}
		}
	})
	t.Run("credential-replacement-and-model-grant", func(t *testing.T) {
		m, probe, auth, _, _ := poolGuardFixture(t, "service")
		revision, identity := poolStage3Identity(t, m, auth)
		replacement := auth.Clone()
		replacement.Metadata["access_token"] = "synthetic-replaced"
		start := make(chan struct{})
		var group sync.WaitGroup
		group.Go(func() {
			<-start
			_, _ = m.Update(context.Background(), replacement)
		})
		group.Go(func() {
			<-start
			_ = m.GrantPoolModelCapability(context.Background(), PoolModelGrant{ExpectedRevision: revision, Identity: identity, Model: "synthetic-native"})
		})
		close(start)
		group.Wait()
		// Whatever the interleaving, the replaced credential must not inherit the
		// old capability: digest binding invalidates records that do not match.
		if err := poolRequestModel(m, "synthetic-native"); err == nil || probe.calls.Load() != 0 {
			t.Fatal("replaced credential inherited model capability")
		}
		if _, err := m.Update(context.Background(), auth); err != nil {
			t.Fatal(err)
		}
		if err := poolRequestModel(m, "synthetic-native"); err == nil || probe.calls.Load() != 0 {
			t.Fatal("restored credential bytes revived capability")
		}
	})
}

func TestPoolStage3RestartAndCorruption(t *testing.T) {
	t.Run("grant-recovers", func(t *testing.T) {
		m, probe, auth, _, _ := poolGuardFixture(t, "service")
		restarted := NewManager(nil, nil, nil)
		restarted.SetConfig(m.runtimeConfigSnapshot())
		restarted.RegisterExecutor(probe)
		if _, err := restarted.Register(context.Background(), auth); err != nil {
			t.Fatal(err)
		}
		if err := poolRequestModel(restarted, "synthetic-native"); err != nil || probe.calls.Load() != 1 {
			t.Fatal("persisted capability grant did not recover", err)
		}
		_, capabilities, err := restarted.PoolModelSnapshot()
		if err != nil || len(capabilities) != 1 || capabilities[0].State != PoolCapabilityVerified {
			t.Fatal("capability snapshot changed on restart", err, capabilities)
		}
	})
	t.Run("trust-generation-mismatch-invalidates", func(t *testing.T) {
		m, probe, _, file, record := poolGuardFixture(t, "service")
		// A new promotion changes the trust generation; grants bound to the old
		// generation must not admit anything until explicitly re-granted.
		record.Revision++
		writePoolGrant(t, file, record)
		auth, _ := m.GetByID("synthetic-pool-account")
		revision, identity := poolStage3Identity(t, m, auth)
		if err := m.PromotePoolIdentities(context.Background(), PoolPromotion{ExpectedRevision: revision, Identities: []PoolIdentityExpectation{identity}}); err != nil {
			t.Fatal(err)
		}
		if err := poolRequestModel(m, "synthetic-native"); err == nil || probe.calls.Load() != 0 {
			t.Fatal("re-promotion inherited old-generation capability")
		}
	})
	t.Run("identity-mismatch-invalidates", func(t *testing.T) {
		m, probe, auth, _, _ := poolGuardFixture(t, "service")
		changed := auth.Clone()
		changed.Metadata["access_token"] = "synthetic-other-credential"
		if _, err := m.Update(context.Background(), changed); err != nil {
			t.Fatal(err)
		}
		if err := poolRequestModel(m, "synthetic-native"); err == nil || probe.calls.Load() != 0 {
			t.Fatal("replaced credential kept model capability")
		}
	})
	t.Run("corrupt-capability-record-fails-closed", func(t *testing.T) {
		m, probe, _, file, record := poolGuardFixture(t, "service")
		record.Capabilities = append(record.Capabilities, PoolModelCapability{AuthID: "synthetic-pool-account", Provider: "codex", CredentialDigest: record.Grants[0].CredentialDigest, Model: "synthetic-native", State: "bogus", Generation: 1})
		record.Revision++
		writePoolGrant(t, file, record)
		if err := poolRequestModel(m, "synthetic-native"); err == nil || probe.calls.Load() != 0 {
			t.Fatal("corrupt capability ledger did not fail closed")
		}
	})
	t.Run("no-startup-auto-grant", func(t *testing.T) {
		m, _, auth, _, _ := poolGuardFixture(t, "service")
		restarted := NewManager(nil, nil, nil)
		restarted.SetConfig(m.runtimeConfigSnapshot())
		if _, err := restarted.Register(context.Background(), auth); err != nil {
			t.Fatal(err)
		}
		_, capabilities, err := restarted.PoolModelSnapshot()
		if err != nil {
			t.Fatal(err)
		}
		if len(capabilities) != 1 {
			t.Fatalf("startup expanded the capability ledger: %+v", capabilities)
		}
	})
}
