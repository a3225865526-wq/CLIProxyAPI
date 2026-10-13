package auth

import (
	"context"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
	ex "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
)

func TestPoolP0FailedDisableAndRecoveryFence(t *testing.T) {
	m, probe, a, _, _ := poolGuardFixture(t, "service")
	installPoolRegistryFixture(t, m)
	if err := m.syncPoolRegistry(context.Background()); err != nil {
		t.Fatal(err)
	}
	current, _ := m.GetByID(a.ID)
	wrapper := m.executors["codex"].(*poolExecutor)
	lease, err := wrapper.begin(context.Background(), current, ex.Request{Model: "synthetic-native"}, ex.Options{}, false, false)
	if err != nil {
		t.Fatal(err)
	}
	defer lease.End("synthetic-test")
	m.SetStore(poolFailingStore{})
	current.Disabled, current.Status = true, StatusDisabled
	if _, err = m.Update(context.Background(), current); err == nil {
		t.Fatal("failed disable returned success")
	}
	after, _ := m.GetByID(a.ID)
	if !after.Disabled {
		t.Fatal("failed disable lost isolation")
	}
	if err = lease.AuthorizeDispatch(); err == nil {
		t.Fatal("preselected lease bypassed failed disable")
	}
	if poolRequest(m) == nil || probe.calls.Load() != 0 {
		t.Fatal("failed disable dispatched mock provider")
	}
	assertPoolRegistryParity(t, m, false)
	if len(registry.GetGlobalRegistry().GetModelsForClient(a.ID)) != 0 {
		t.Fatal("failed disable retained Registry models")
	}
	beforeGeneration := after.Generation
	after.Disabled, after.Status = false, StatusActive
	if _, err = m.Update(context.Background(), after); err == nil {
		t.Fatal("failed recovery returned success")
	}
	after, _ = m.GetByID(a.ID)
	if !after.Disabled || after.Generation != beforeGeneration {
		t.Fatal("failed recovery published candidate")
	}
	if _, err = wrapper.begin(context.Background(), current, ex.Request{Model: "synthetic-native"}, ex.Options{}, false, false); err == nil {
		t.Fatal("failed recovery opened dispatch fence")
	}
	if poolRequest(m) == nil || probe.calls.Load() != 0 {
		t.Fatal("failed recovery dispatched mock provider")
	}
}
