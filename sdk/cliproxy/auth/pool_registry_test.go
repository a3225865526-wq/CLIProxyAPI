package auth

import (
	"context"
	"errors"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
	ex "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func installPoolRegistryFixture(t *testing.T, m *Manager) {
	t.Helper()
	m.SetPoolRegistrySync(func(context.Context) error {
		for _, a := range m.List() {
			if !m.PublishPoolModels(a, a.Provider, []*registry.ModelInfo{{ID: "synthetic-native"}, {ID: "synthetic-other"}}) {
				return ErrPoolGuard
			}
		}
		return nil
	})
}
func assertPoolRegistryParity(t *testing.T, m *Manager, eligible bool) {
	t.Helper()
	p, err := m.PoolRequestPreflight(context.Background(), "synthetic-native", ex.Options{OriginalRequest: []byte(`{"model":"synthetic-native","tools":[]}`)})
	if err != nil {
		t.Fatal(err)
	}
	if (p.EligibleCount == 1) != eligible || (len(m.PoolModelProviders("synthetic-native")) == 1) != eligible {
		t.Fatalf("preflight=%+v providers=%v eligible=%t", p, m.PoolModelProviders("synthetic-native"), eligible)
	}
}
func TestPoolRegistryMarkResultKeepsPublicationCurrent(t *testing.T) {
	m, _, a, _, _ := poolGuardFixture(t, "service")
	installPoolRegistryFixture(t, m)
	explicitPoolPromotion(t, m)
	assertPoolRegistryParity(t, m, true)
	before, _ := m.GetByID(a.ID)
	m.MarkResult(context.Background(), Result{AuthID: a.ID, Provider: a.Provider, Model: "synthetic-native", Success: true})
	after, _ := m.GetByID(a.ID)
	if after.Generation != before.Generation+1 {
		t.Fatalf("generation=%d, want %d", after.Generation, before.Generation+1)
	}
	assertPoolRegistryParity(t, m, true)
	for range 3 {
		m.MarkResult(context.Background(), Result{AuthID: a.ID, Provider: a.Provider, Model: "synthetic-native", Success: true})
		assertPoolRegistryParity(t, m, true)
	}
	if m.PublishPoolModels(before, a.Provider, []*registry.ModelInfo{{ID: "synthetic-native"}}) {
		t.Fatal("old result snapshot published")
	}
	rev, identity := poolExpectation(t, m)
	if err := m.RevokePoolModelCapability(context.Background(), PoolModelRevoke{ExpectedRevision: rev, Identity: identity, Model: "synthetic-native"}); err != nil {
		t.Fatal(err)
	}
	m.MarkResult(context.Background(), Result{AuthID: a.ID, Provider: a.Provider, Model: "synthetic-native", Success: true})
	assertPoolRegistryParity(t, m, false)
}

func TestPoolRegistryMarkResultConcurrentRevoke(t *testing.T) {
	m, _, a, _, _ := poolGuardFixture(t, "service")
	installPoolRegistryFixture(t, m)
	explicitPoolPromotion(t, m)
	old, _ := m.GetByID(a.ID)
	rev, identity := poolExpectation(t, m)
	var wg sync.WaitGroup
	wg.Go(func() {
		for range 30 {
			m.MarkResult(context.Background(), Result{AuthID: a.ID, Provider: a.Provider, Model: "synthetic-native", Success: true})
		}
	})
	err := m.RevokePoolModelCapability(context.Background(), PoolModelRevoke{ExpectedRevision: rev, Identity: identity, Model: "synthetic-native"})
	wg.Wait()
	if err != nil {
		t.Fatal(err)
	}
	m.PublishPoolModels(old, a.Provider, []*registry.ModelInfo{{ID: "synthetic-native"}})
	assertPoolRegistryParity(t, m, false)
	if len(registry.GetGlobalRegistry().GetModelsForClient(a.ID)) != 0 {
		t.Fatal("result publication restored revoked model")
	}
}
func TestPoolRegistryLifecycle(t *testing.T) {
	m, probe, a, _, _ := poolGuardFixture(t, "service")
	registry.GetGlobalRegistry().UnregisterClient(a.ID)
	installPoolRegistryFixture(t, m)
	old := a.Clone()
	explicitPoolPromotion(t, m)
	assertPoolRegistryParity(t, m, true)
	if m.PublishPoolModels(old, a.Provider, []*registry.ModelInfo{{ID: "synthetic-native"}}) {
		t.Fatal("stale generation published")
	}
	if err := poolRequest(m); err != nil {
		t.Fatal("runtime eligible request rejected", err)
	}
	if probe.calls.Load() != 1 {
		t.Fatal("mock dispatch parity")
	}
	current, _ := m.GetByID(a.ID)
	if _, err := m.Update(context.Background(), current.Clone()); err != nil {
		t.Fatal(err)
	}
	assertPoolRegistryParity(t, m, false)
	if err := m.syncPoolRegistry(context.Background()); err != nil {
		t.Fatal(err)
	}
	assertPoolRegistryParity(t, m, true)
	rev, identity := poolExpectation(t, m)
	if err := m.RevokePoolModelCapability(context.Background(), PoolModelRevoke{ExpectedRevision: rev, Identity: identity, Model: "synthetic-native"}); err != nil {
		t.Fatal(err)
	}
	assertPoolRegistryParity(t, m, false)
	if len(registry.GetGlobalRegistry().GetModelsForClient(a.ID)) != 0 {
		t.Fatal("revoked model published")
	}
	if poolRequest(m) == nil || probe.calls.Load() != 1 {
		t.Fatal("revoked runtime dispatched")
	}
}
func TestPoolRegistryExpiryDisabledAndFailure(t *testing.T) {
	for _, mode := range []string{"expired", "disabled", "callback-failure", "revoked"} {
		t.Run(mode, func(t *testing.T) {
			m, probe, a, _, _ := poolGuardFixture(t, "service")
			installPoolRegistryFixture(t, m)
			explicitPoolPromotion(t, m)
			switch mode {
			case "expired":
				future := time.Now().Add(time.Hour)
				m.poolGuard.now = func() time.Time { return future }
			case "disabled":
				current, _ := m.GetByID(a.ID)
				current.Disabled = true
				if _, err := m.Update(context.Background(), current); err != nil {
					t.Fatal(err)
				}
				if err := m.syncPoolRegistry(context.Background()); err != nil {
					t.Fatal(err)
				}
			case "callback-failure":
				m.SetPoolRegistrySync(func(context.Context) error { return errors.New("synthetic publication failure") })
				if m.syncPoolRegistry(context.Background()) == nil {
					t.Fatal("failure ignored")
				}
			case "revoked":
				poolRevoke(t, m)
			}
			assertPoolRegistryParity(t, m, false)
			if poolRequest(m) == nil || probe.calls.Load() != 0 {
				t.Fatal("fail closed runtime bypass")
			}
		})
	}
}
func TestPoolRegistryConcurrentCASAndStalePublication(t *testing.T) {
	m, _, a, _, _ := poolGuardFixture(t, "service")
	installPoolRegistryFixture(t, m)
	explicitPoolPromotion(t, m)
	old, _ := m.GetByID(a.ID)
	rev, identity := poolExpectation(t, m)
	var wg sync.WaitGroup
	var won atomic.Int32
	for range 8 {
		wg.Go(func() {
			if m.RevokePoolModelCapability(context.Background(), PoolModelRevoke{ExpectedRevision: rev, Identity: identity, Model: "synthetic-native"}) == nil {
				won.Add(1)
			}
		})
	}
	wg.Wait()
	if won.Load() != 1 {
		t.Fatalf("CAS winners=%d", won.Load())
	}
	for range 8 {
		wg.Go(func() {
			for range 20 {
				m.PublishPoolModels(old, a.Provider, []*registry.ModelInfo{{ID: "synthetic-native"}})
			}
		})
	}
	wg.Wait()
	assertPoolRegistryParity(t, m, false)
	if len(registry.GetGlobalRegistry().GetModelsForClient(a.ID)) != 0 {
		t.Fatal("stale publication restored capability")
	}
}
func TestLocalResolutionProofRejectsAttemptedAndTerminal(t *testing.T) {
	local := NewLocalModelResolutionError(`{"error":{"code":"model_not_found"}}`)
	if !IsLocalModelResolutionError(local) {
		t.Fatal("typed local proof missing")
	}
	if IsLocalModelResolutionError(markUpstreamExecutionAttempt(local)) || IsLocalModelResolutionError(NewTerminalAuthError(&Error{Code: "auth_not_found"}, local)) {
		t.Fatal("attempted/terminal claimed zero dispatch")
	}
	if IsLocalModelResolutionError(errors.New(local.Error())) {
		t.Fatal("body forged typed proof")
	}
}
