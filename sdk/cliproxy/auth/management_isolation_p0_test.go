package auth

import (
	"context"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
	ex "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
)

func TestPoolManagementIsolationP0LegacyAndMalformed(t *testing.T) {
	for _, tc := range []struct {
		name     string
		disabled bool
		flag     any
		present  bool
		isolated bool
	}{
		{"legacy-enabled", false, nil, false, false},
		{"legacy-disabled", true, nil, false, true},
		{"explicit-pending", true, false, true, false},
		{"contradictory", false, true, true, true},
		{"string", false, "false", true, true},
		{"null", false, nil, true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := &Auth{ID: "synthetic", Provider: "codex", Disabled: tc.disabled, Status: StatusActive, Metadata: map[string]any{}}
			if tc.present {
				a.Metadata[ManagementDisabledKey] = tc.flag
			}
			ApplyPersistentManagementIsolation(a)
			if ManagementIsolation(a) != tc.isolated {
				t.Fatal("migration isolation mismatch")
			}
			if tc.isolated {
				if !a.Disabled || a.Status != StatusDisabled {
					t.Fatal("isolation did not normalize runtime")
				}
				// The independent field must gate even contradictory runtime flags.
				a.Disabled, a.Status = false, StatusActive
				if _, _, schedulable := isSchedulableAuth(a); schedulable {
					t.Fatal("scheduler ignored management isolation")
				}
				if available, errAvailable := getAvailableAuths([]*Auth{a}, "codex", "", time.Now()); errAvailable == nil || len(available) != 0 {
					t.Fatal("selector ignored management isolation")
				}
			}
		})
	}
}

func TestPoolManagementIsolationP0StaleLeaseAndCAS(t *testing.T) {
	m, probe, a, _, _ := poolGuardFixture(t, "service")
	installPoolRegistryFixture(t, m)
	if errSync := m.syncPoolRegistry(context.Background()); errSync != nil {
		t.Fatal(errSync)
	}
	current, _ := m.GetByID(a.ID)
	wrapper := m.executors["codex"].(*poolExecutor)
	lease, errLease := wrapper.begin(context.Background(), current, ex.Request{Model: "synthetic-native"}, ex.Options{}, false, false)
	if errLease != nil {
		t.Fatal(errLease)
	}
	defer lease.End("synthetic-test")
	m.SetStore(poolFailingStore{})
	if _, errDisable := m.UpdateManagementStatus(context.Background(), current, true); errDisable == nil {
		t.Fatal("synthetic persistence failure reported committed")
	}
	if errDispatch := lease.AuthorizeDispatch(); errDispatch == nil {
		t.Fatal("stale lease authorized management-disabled credential")
	}
	if poolRequest(m) == nil || probe.calls.Load() != 0 {
		t.Fatal("management-disabled request reached synthetic provider")
	}
	assertPoolRegistryParity(t, m, false)
	if len(registry.GetGlobalRegistry().GetModelsForClient(a.ID)) != 0 {
		t.Fatal("management disable retained Registry")
	}
	if _, errStale := m.UpdateManagementStatus(context.Background(), current, true); errStale == nil {
		t.Fatal("stale explicit status snapshot accepted")
	}
	installed, _ := m.GetByID(a.ID)
	installed.Metadata[ManagementDisabledKey] = false
	installed.Disabled, installed.Status = false, StatusActive
	// Simulate a watcher trying to replace all flags, not only Disabled.
	if _, errWatcher := m.Update(WithSkipPersist(context.Background()), installed); errWatcher != nil {
		t.Fatal(errWatcher)
	}
	installed, _ = m.GetByID(a.ID)
	if !ManagementIsolation(installed) || !installed.Disabled {
		t.Fatal("watcher removed management isolation")
	}
}
