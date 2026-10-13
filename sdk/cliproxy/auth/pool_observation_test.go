//go:build clearapi_staging_observability

package auth

import (
	"context"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
	"testing"
)

func TestPoolObservationDoesNotChangeAdmission(t *testing.T) {
	t.Setenv("CLEARAPI_PG02_OBSERVE", "true")
	m, probe, a, _, _ := poolGuardFixture(t, "service")
	installPoolRegistryFixture(t, m)
	explicitPoolPromotion(t, m)
	before, _ := m.GetByID(a.ID)
	ctx := poolObservationContext(context.Background(), cliproxyexecutor.Options{})
	fields := poolObservationFields(ctx, "read_only_projection")
	m.mu.RLock()
	version := m.poolRegistryVersions[a.ID]
	m.poolObservationVersionsLocked(fields, a.ID)
	m.mu.RUnlock()
	for range 5 {
		_ = m.poolObservationSnapshot()
	}
	after, _ := m.GetByID(a.ID)
	if before.Generation != after.Generation || m.poolRegistryVersions[a.ID] != version || probe.calls.Load() != 0 {
		t.Fatal("observer mutated publication or dispatched")
	}
	if fields["auth_generation"] != after.Generation || fields["registry_generation"] != version.generation || fields["registry_revision"] != version.revision {
		t.Fatal("projection is not actual runtime state")
	}
	if _, present := fields["credential_digest"]; present {
		t.Fatal("observer unnecessarily includes credential material")
	}
	assertPoolRegistryParity(t, m, true)
	m.MarkResult(ctx, Result{AuthID: a.ID, Provider: a.Provider, Model: "synthetic-native", Success: true})
	assertPoolRegistryParity(t, m, true)
}
