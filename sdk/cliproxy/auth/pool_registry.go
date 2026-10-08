package auth

import (
	"context"
	"reflect"
	"slices"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
)

type poolRegistryVersion struct {
	generation uint64
	revision   uint64
}

// SetPoolRegistrySync installs the host's synchronous model publication callback.
// The callback runs after security commit locks are released and never persists credentials.
func (m *Manager) SetPoolRegistrySync(syncModels func(context.Context) error) {
	m.mu.Lock()
	m.poolRegistrySync = syncModels
	m.poolRegistryVersions = make(map[string]poolRegistryVersion)
	m.mu.Unlock()
}

func (m *Manager) syncPoolRegistry(ctx context.Context) error {
	m.poolRegistrySyncMu.Lock()
	defer m.poolRegistrySyncMu.Unlock()
	m.mu.RLock()
	callback := m.poolRegistrySync
	m.mu.RUnlock()
	if callback == nil {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	// A durable security commit must finish publication even if its HTTP caller disconnects.
	if err := callback(context.WithoutCancel(ctx)); err != nil {
		m.mu.Lock()
		clear(m.poolRegistryVersions)
		m.mu.Unlock()
		return err
	}
	m.poolGuard.mu.Lock()
	defer m.poolGuard.mu.Unlock()
	m.mu.RLock()
	defer m.mu.RUnlock()
	record, err := m.loadPoolGrants(true)
	if err != nil {
		return err
	}
	for _, a := range m.auths {
		if a != nil && !a.Disabled && !m.poolRegistryCurrent(a, record) {
			return ErrPoolGuard
		}
	}
	return nil
}

// PublishPoolModels atomically validates the current auth and policy before publishing.
// Watcher snapshots with an old generation cannot overwrite a later CAS publication.
func (m *Manager) PublishPoolModels(snapshot *Auth, provider string, models []*registry.ModelInfo) bool {
	if m == nil || m.poolGuard == nil || snapshot == nil {
		return false
	}
	m.poolGuard.mu.Lock()
	defer m.poolGuard.mu.Unlock()
	m.mu.Lock()
	defer m.mu.Unlock()
	a := m.auths[snapshot.ID]
	if a == nil || a.Generation != snapshot.Generation || a.Disabled != snapshot.Disabled || PoolCredentialDigest(a) != PoolCredentialDigest(snapshot) {
		return false
	}
	record, err := m.loadPoolGrants(true)
	allowed := make([]*registry.ModelInfo, 0, len(models))
	if err == nil && !a.Disabled && provider == a.Provider {
		for _, info := range models {
			if info != nil && m.poolModelCheck(record, a, m.selectionModelForAuth(a, info.ID), nil) == nil {
				allowed = append(allowed, info)
			}
		}
	}
	reg := registry.GetGlobalRegistry()
	if reflect.DeepEqual(reg.GetModelsForClient(a.ID), allowed) {
		// Duplicate events retain registry epochs and cooldown projections.
	} else if len(allowed) == 0 {
		reg.UnregisterClient(a.ID)
	} else {
		reg.RegisterClient(a.ID, provider, allowed)
	}
	if m.poolRegistryVersions == nil {
		m.poolRegistryVersions = make(map[string]poolRegistryVersion)
	}
	delete(m.poolRegistryVersions, a.ID)
	if err == nil {
		m.poolRegistryVersions[a.ID] = poolRegistryVersion{a.Generation, record.Revision}
	}
	if m.scheduler != nil {
		m.structuralEpoch.Add(1)
		m.scheduler.upsertAuth(a.Clone())
	}
	return err == nil
}

// Caller holds manager.mu. Admission is gated on the same publication revision.
func (m *Manager) poolRegistryCurrent(a *Auth, record *PoolGrantFile) bool {
	if m.poolRegistrySync == nil {
		return true
	}
	v, ok := m.poolRegistryVersions[a.ID]
	return ok && v.generation == a.Generation && v.revision == record.Revision
}

func (m *Manager) poolRegistrySupports(a *Auth, model string, record *PoolGrantFile) bool {
	if !m.poolRegistryCurrent(a, record) {
		return false
	}
	resolved := m.selectionModelForAuth(a, model)
	return slices.ContainsFunc(registry.GetGlobalRegistry().GetModelsForClient(a.ID), func(info *registry.ModelInfo) bool {
		return info != nil && (info.ID == model || info.ID == canonicalModelKey(model) || info.ID == resolved)
	})
}

// PoolModelProviders resolves only current, admitted registrations. Expired floors
// and revoked capabilities fail closed immediately, without waiting for a watcher.
func (m *Manager) PoolModelProviders(model string) []string {
	if m == nil || m.poolGuard == nil {
		return nil
	}
	m.poolGuard.mu.Lock()
	defer m.poolGuard.mu.Unlock()
	m.mu.RLock()
	defer m.mu.RUnlock()
	record, err := m.loadPoolGrants(true)
	if err != nil {
		return nil
	}
	providers := []string{}
	for _, a := range m.auths {
		if a == nil || a.Disabled || !m.poolRegistrySupports(a, model, record) || m.poolModelCheck(record, a, m.selectionModelForAuth(a, model), nil) != nil {
			continue
		}
		if _, ok := m.executorLocked(executorKeyFromAuth(a)); !ok {
			continue
		}
		available, _, err := m.availableAuthsForSelector(m.selector, []*Auth{a}, "mixed", model, time.Now())
		if err != nil || len(available) == 0 {
			continue
		}
		if !slices.Contains(providers, a.Provider) {
			providers = append(providers, a.Provider)
		}
	}
	slices.Sort(providers)
	return providers
}
