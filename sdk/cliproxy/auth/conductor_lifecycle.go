package auth

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	internalconfig "github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
	log "github.com/sirupsen/logrus"
)

// SetRetryConfig updates additional credential retry rounds, the per-round credential limit, and the cooldown wait interval.
func (m *Manager) SetRetryConfig(retry int, maxRetryInterval time.Duration, maxRetryCredentials int) {
	if m == nil {
		return
	}
	if retry < 0 {
		retry = 0
	}
	if maxRetryCredentials < 0 {
		maxRetryCredentials = 0
	}
	if maxRetryInterval < 0 {
		maxRetryInterval = 0
	}
	m.requestRetry.Store(int32(retry))
	m.maxRetryCredentials.Store(int32(maxRetryCredentials))
	m.maxRetryInterval.Store(maxRetryInterval.Nanoseconds())
}

// RegisterExecutor registers a provider executor with the manager.
func (m *Manager) RegisterExecutor(executor ProviderExecutor) {
	if executor == nil {
		return
	}
	if m.poolGuard != nil {
		executor = &poolExecutor{ProviderExecutor: executor, manager: m}
	}
	provider := strings.TrimSpace(executor.Identifier())
	if provider == "" {
		return
	}

	var replaced ProviderExecutor
	var toReschedule []string
	m.mu.Lock()
	replaced = m.executors[provider]
	m.executors[provider] = executor
	for id, auth := range m.auths {
		if auth != nil && strings.EqualFold(executorKeyFromAuth(auth), provider) {
			toReschedule = append(toReschedule, id)
		}
	}
	m.mu.Unlock()

	for _, id := range toReschedule {
		m.queueRefreshReschedule(id)
	}

	if replaced == nil || replaced == executor {
		return
	}
	if closer, ok := replaced.(ExecutionSessionCloser); ok && closer != nil {
		closer.CloseExecutionSession(CloseAllExecutionSessionsID)
	}
}

// UnregisterExecutor removes the executor associated with the provider key.
func (m *Manager) UnregisterExecutor(provider string) {
	provider = strings.ToLower(strings.TrimSpace(provider))
	if provider == "" {
		return
	}
	m.mu.Lock()
	delete(m.executors, provider)
	m.mu.Unlock()
}

// Register inserts a new auth entry into the manager.
func (m *Manager) Register(ctx context.Context, auth *Auth) (*Auth, error) {
	if auth == nil {
		return nil, nil
	}
	if m.poolGuard != nil {
		m.poolGuard.mu.Lock()
		defer m.poolGuard.mu.Unlock()
	}
	NormalizeCredentialMetadata(auth.Metadata)
	if m.poolGuard != nil {
		ApplyPersistentManagementIsolation(auth)
	}
	if errWeight := ValidateAuthWeight(auth); errWeight != nil {
		return nil, fmt.Errorf("register auth: %w", errWeight)
	}
	if auth.ID == "" {
		auth.ID = uuid.NewString()
	}
	if m.poolGuard != nil {
		if m.poolGuard.role != "service" {
			quarantinePoolAuth(auth)
		} else {
			// A newly appearing file never enrolls itself. Only a separate grant
			// can permit a matching credential; disabled imports stay disabled.
			if _, err := m.poolGrant(auth, firstPoolGrantModel(m, auth), nil); err != nil {
				quarantinePoolAuth(auth)
			}
		}
	}
	now := time.Now()
	if auth.Generation == 0 {
		auth.Generation = 1
		if recoveryGeneration, okRecovery := PersistedRecoveryGeneration(auth); okRecovery {
			auth.Generation = recoveryGeneration
		}
	}
	if auth.CreatedAt.IsZero() {
		auth.CreatedAt = now
	}
	auth.UpdatedAt = now
	cooldownStateChanged := normalizeModelStates(auth)
	if m.cooldownDisabledForAuth(auth) || auth.Disabled || auth.Status == StatusDisabled {
		cooldownStateChanged = clearCooldownStateForAuth(auth, now) || cooldownStateChanged
	}
	auth.EnsureIndex()
	m.mu.Lock()
	if m.authEpochs == nil {
		m.authEpochs = make(map[string]uint64)
	}
	if existing, exists := m.auths[auth.ID]; exists && existing != nil && existing.RegistrationEpoch > m.authEpochs[auth.ID] {
		m.authEpochs[auth.ID] = existing.RegistrationEpoch
	}
	if auth.RegistrationEpoch > m.authEpochs[auth.ID] {
		m.authEpochs[auth.ID] = auth.RegistrationEpoch
	}
	if existing := m.auths[auth.ID]; m.poolGuard != nil && existing != nil && ManagementIsolation(existing) {
		if auth.Metadata == nil {
			auth.Metadata = make(map[string]any)
		}
		auth.Metadata[ManagementDisabledKey] = true
		quarantinePoolAuth(auth)
	}
	m.authEpochs[auth.ID]++
	auth.RegistrationEpoch = m.authEpochs[auth.ID]
	auth.Generation = 1
	if recoveryGeneration, okRecovery := PersistedRecoveryGeneration(auth); okRecovery {
		auth.Generation = recoveryGeneration
	}
	if err := m.invalidatePoolReplacement(ctx, m.auths[auth.ID], auth); err != nil {
		m.mu.Unlock()
		return nil, err
	}
	authClone := auth.Clone()
	m.auths[auth.ID] = authClone
	m.mu.Unlock()
	if !shouldDeferAPIKeyModelAliasRebuild(ctx) {
		m.rebuildAPIKeyModelAliasFromRuntimeConfig()
	}
	if m.scheduler != nil {
		m.scheduler.upsertAuth(authClone.Clone())
	}
	m.structuralEpoch.Add(1)
	m.queueRefreshReschedule(auth.ID)
	_ = m.persist(ctx, auth)
	m.hook.OnAuthRegistered(ctx, auth.Clone())
	if cooldownStateChanged {
		m.persistCooldownStates(context.Background())
	}
	return auth.Clone(), nil
}

type updateAuthMode int

const (
	updateModeReplace updateAuthMode = iota
	updateModeRefresh
	updateModePrepare
)

// UpdatePreparedAuth atomically merges request preparation results into the latest runtime auth
// under the manager lock, preserving concurrent modifications without modifying refresh lifecycle fields.
func (m *Manager) UpdatePreparedAuth(ctx context.Context, base, updated *Auth) (*Auth, error) {
	return m.updateInternal(ctx, base, updated, updateModePrepare)
}

// UpdateRefreshedAuth atomically merges refresh results into the latest runtime auth
// under the manager lock, preserving concurrent modifications (proxy_url, notes, weights, etc.).
func (m *Manager) UpdateRefreshedAuth(ctx context.Context, base, updated *Auth) (*Auth, error) {
	return m.updateInternal(ctx, base, updated, updateModeRefresh)
}

// Update replaces an existing auth entry and notifies hooks.
func (m *Manager) Update(ctx context.Context, auth *Auth) (*Auth, error) {
	return m.updateInternal(ctx, nil, auth, updateModeReplace)
}

func (m *Manager) updateInternal(ctx context.Context, base, auth *Auth, mode updateAuthMode) (*Auth, error) {
	if auth == nil || auth.ID == "" {
		return nil, nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if m.poolGuard != nil {
		m.poolGuard.mu.Lock()
		defer m.poolGuard.mu.Unlock()
	}
	NormalizeCredentialMetadata(auth.Metadata)
	if errWeight := ValidateAuthWeight(auth); errWeight != nil {
		return nil, fmt.Errorf("update auth: %w", errWeight)
	}
	m.mu.Lock()
	existing, ok := m.auths[auth.ID]
	if !ok || existing == nil {
		m.mu.Unlock()
		if _, explicit := ctx.Value(managementStatusKey{}).(managementStatusExpectation); explicit {
			return nil, fmt.Errorf("management status: identity removed")
		}
		return nil, nil
	}
	management, explicitManagement := ctx.Value(managementStatusKey{}).(managementStatusExpectation)
	// A watcher can have synthesized isolation before the recovery WAL commit
	// and queued that unversioned snapshot behind this transaction. Recheck the
	// durable enabled account and COMMITTED proof while holding the identity lock;
	// a current disk disable (or unverifiable proof) must still take effect.
	if !explicitManagement && m.staleRecoveryIsolationSnapshot(ctx, existing, auth) {
		current := existing.Clone()
		m.mu.Unlock()
		return current, nil
	}
	if explicitManagement && (management.id != existing.ID || management.digest != PoolCredentialDigest(existing) || management.generation != existing.Generation || management.epoch != existing.RegistrationEpoch) {
		m.mu.Unlock()
		return nil, fmt.Errorf("management status: stale identity or generation")
	}
	recovery, isRecovery := ctx.Value(managementRecoveryContextKey{}).(managementRecoveryPlan)
	recoveryAttempt := existing.Disabled && !auth.Disabled
	if isRecovery {
		if !existing.Disabled || !ManagementIsolation(existing) {
			m.mu.Unlock()
			return nil, &ManagementRecoveryOutcomeError{Status: "NOT_COMMITTED", OpID: recovery.opID, Err: fmt.Errorf("account is not durably isolated")}
		}
		if management.revision != recovery.expected.revision {
			m.mu.Unlock()
			return nil, &ManagementRecoveryOutcomeError{Status: "NOT_COMMITTED", OpID: recovery.opID, Err: fmt.Errorf("stale pool revision")}
		}
		currentPool, errPool := m.poolGrants()
		if errPool != nil || currentPool.Revision != recovery.expected.revision {
			m.mu.Unlock()
			return nil, &ManagementRecoveryOutcomeError{Status: "NOT_COMMITTED", OpID: recovery.opID, Err: fmt.Errorf("stale pool revision")}
		}
	}
	if m.authEpochs == nil {
		m.authEpochs = make(map[string]uint64)
	}
	if existing.RegistrationEpoch > m.authEpochs[auth.ID] {
		m.authEpochs[auth.ID] = existing.RegistrationEpoch
	}
	if (mode == updateModeRefresh || mode == updateModePrepare) && base != nil && existing.RegistrationEpoch != base.RegistrationEpoch {
		m.mu.Unlock()
		return nil, fmt.Errorf("update auth %s: stale registration epoch %d != %d", auth.ID, base.RegistrationEpoch, existing.RegistrationEpoch)
	}
	if mode == updateModeRefresh {
		merged := MergeRefreshedAuth(base, existing, auth)
		if merged != nil {
			auth = merged
			NormalizeCredentialMetadata(auth.Metadata)
		}
	} else if mode == updateModePrepare {
		merged := MergePreparedAuth(base, existing, auth)
		if merged != nil {
			auth = merged
			NormalizeCredentialMetadata(auth.Metadata)
		}
	}
	if m.poolGuard != nil && auth.Disabled {
		if auth.Metadata == nil {
			auth.Metadata = make(map[string]any)
		}
		// Any pool update that installs an operator-disabled runtime state must
		// carry the durable management fence, including legacy direct callers.
		auth.Metadata[ManagementDisabledKey] = true
	}
	if !explicitManagement && ManagementIsolation(existing) {
		if auth.Metadata == nil {
			auth.Metadata = make(map[string]any)
		}
		auth.Metadata[ManagementDisabledKey] = true
		quarantinePoolAuth(auth)
	}
	if err := m.invalidatePoolReplacement(ctx, existing, auth); err != nil {
		m.mu.Unlock()
		return nil, err
	}
	if m.poolGuard != nil {
		if ManagementIsolation(auth) {
			quarantinePoolAuth(auth)
		}
		if (mode == updateModeRefresh || mode == updateModePrepare || shouldSkipPersist(ctx)) && existing.Disabled {
			quarantinePoolAuth(auth)
		}
		if _, errPoolGrant := m.poolGrant(auth, firstPoolGrantModel(m, auth), nil); errPoolGrant != nil {
			if isRecovery {
				m.mu.Unlock()
				return nil, &ManagementRecoveryOutcomeError{Status: "NOT_COMMITTED", OpID: recovery.opID, Err: fmt.Errorf("recovery authorization is not currently granted: %w", errPoolGrant)}
			}
			quarantinePoolAuth(auth)
		}
	}
	if auth.RegistrationEpoch != 0 && auth.RegistrationEpoch < m.authEpochs[auth.ID] {
		m.mu.Unlock()
		return nil, fmt.Errorf("update auth %s: stale registration epoch %d < %d", auth.ID, auth.RegistrationEpoch, m.authEpochs[auth.ID])
	}
	if auth.RegistrationEpoch >= m.authEpochs[auth.ID] {
		m.authEpochs[auth.ID] = auth.RegistrationEpoch
	} else if auth.RegistrationEpoch == 0 {
		auth.RegistrationEpoch = m.authEpochs[auth.ID]
	}
	if !auth.indexAssigned && auth.Index == "" {
		auth.Index = existing.Index
		auth.indexAssigned = existing.indexAssigned
	}
	auth.Success = existing.Success
	auth.Failed = existing.Failed
	auth.recentRequests = existing.recentRequests
	if auth.Generation <= existing.Generation {
		auth.Generation = existing.Generation + 1
	} else {
		auth.Generation++
	}
	var recoveryOperation ManagementRecoveryOperation
	if isRecovery {
		recoveryOperation = ManagementRecoveryOperation{
			OpID: recovery.opID, AuthID: auth.ID, CredentialDigest: PoolCredentialDigest(auth),
			Generation: auth.Generation, Revision: recovery.expected.revision,
			State: ManagementRecoveryPrepared, TargetDisabled: false,
		}
		if recoveryStore, okStore := m.store.(ManagementRecoveryStore); !okStore {
			m.mu.Unlock()
			return nil, &ManagementRecoveryOutcomeError{Status: "NOT_COMMITTED", OpID: recovery.opID, Err: fmt.Errorf("backend does not support FileStore WAL recovery")}
		} else if errPrepare := recoveryStore.PrepareManagementRecovery(ctx, auth.Clone(), recoveryOperation); errPrepare != nil {
			m.mu.Unlock()
			var outcomeErr *ManagementRecoveryOutcomeError
			if errors.As(errPrepare, &outcomeErr) {
				return nil, outcomeErr
			}
			return nil, &ManagementRecoveryOutcomeError{Status: "NOT_COMMITTED", OpID: recovery.opID, Err: errPrepare}
		}
		if auth.Metadata == nil {
			auth.Metadata = make(map[string]any)
		}
		auth.Metadata[RecoveryOpIDKey] = recoveryOperation.OpID
		auth.Metadata[RecoveryGenerationKey] = recoveryOperation.Generation
		auth.Metadata[RecoveryRevisionKey] = recoveryOperation.Revision
		auth.Metadata[RecoveryStateKey] = string(ManagementRecoveryPrepared)
	}
	cooldownStateChanged := false
	if !existing.Disabled && existing.Status != StatusDisabled && !auth.Disabled && auth.Status != StatusDisabled {
		if len(auth.ModelStates) == 0 && len(existing.ModelStates) > 0 {
			auth.ModelStates = existing.ModelStates
		}
		credChanged := CredentialsChanged(existing, auth)
		if credChanged {
			if hasUnauthorizedAuthFailure(existing) || (auth.LastError != nil && isUnauthorizedError(auth.LastError)) {
				auth.Unavailable = false
				auth.LastError = nil
				auth.StatusMessage = ""
				auth.Status = StatusActive
			}
			resumed := clearUnauthorizedModelStates(auth, time.Now())
			if len(resumed) > 0 {
				cooldownStateChanged = true
			}
		}
		if existing.Quota.Exceeded && existing.Quota.Reason == "credential_quota" && existing.Quota.NextRecoverAt.After(time.Now()) {
			auth.Unavailable = existing.Unavailable
			auth.NextRetryAfter = existing.NextRetryAfter
			auth.Quota = existing.Quota
			if auth.Status == StatusActive {
				auth.Status = existing.Status
			}
		}
	}
	now := time.Now()
	auth.UpdatedAt = now
	cooldownStateChanged = normalizeModelStates(auth) || cooldownStateChanged
	if m.cooldownDisabledForAuth(auth) || auth.Disabled || auth.Status == StatusDisabled {
		cooldownStateChanged = clearCooldownStateForAuth(auth, now) || cooldownStateChanged
	}
	auth.EnsureIndex()
	// A minted Meta key must reach the configured store before requests can use it.
	// Keep the epoch check, save and installation together so a concurrent reload
	// or removal cannot let an obsolete mint overwrite the credential on disk.
	persistMetaMint := (mode == updateModePrepare || mode == updateModeRefresh) && strings.EqualFold(strings.TrimSpace(auth.Provider), "meta")
	if persistMetaMint {
		if errPersist := m.persist(ctx, auth); errPersist != nil {
			m.mu.Unlock()
			return nil, fmt.Errorf("persist meta auth: %w", errPersist)
		}
	}
	authClone := auth.Clone()
	disabledChanged := existing != nil && existing.Disabled != auth.Disabled
	isDisabledUpdate := auth.Disabled || disabledChanged
	// Disabled transitions are security-critical. Persist the candidate before
	// granting new dispatch eligibility; failed disables publish isolation only.
	if isDisabledUpdate && !persistMetaMint {
		persistCtx := ctx
		if isRecovery {
			persistCtx = WithManagementRecoveryDurability(ctx)
		}
		errPersist := m.persist(persistCtx, authClone)
		if errPersist == nil && m.poolGuard != nil && explicitManagement && !isRecovery && authClone.Disabled {
			if durable, supported := m.store.(ManagementDisableStore); supported {
				errPersist = durable.ConfirmManagementDisable(ctx, authClone)
			} else {
				errPersist = fmt.Errorf("management disable: backend cannot confirm durable isolation")
			}
		}
		if errPersist != nil && explicitManagement && !isRecovery && authClone.Disabled && (recoveryAttempt || (existing.Disabled && ManagementIsolation(existing))) {
			if durable, supported := m.store.(ManagementDisableStore); supported && durable.ConfirmManagementDisable(ctx, authClone) == nil {
				errPersist = nil
			}
		}
		if errPersist != nil {
			// Save may have committed before reporting an error. A failed disable
			// remains isolated in memory; it is never reported as a durable success.
			// A failed recovery leaves the already-disabled entry untouched.
			if authClone.Disabled && !isRecovery && !recoveryAttempt {
				quarantinePoolAuth(authClone)
				m.auths[auth.ID] = authClone
				delete(m.poolRegistryVersions, auth.ID)
				registry.GetGlobalRegistry().UnregisterClient(auth.ID)
				if m.scheduler != nil {
					m.scheduler.upsertAuth(authClone.Clone())
				}
				m.structuralEpoch.Add(1)
			}
			m.mu.Unlock()
			if isRecovery {
				verified, errVerify := m.store.(ManagementRecoveryStore).VerifyManagementRecovery(ctx, authClone, recoveryOperation)
				if errVerify == nil && verified == ManagementRecoveryPrepared {
					return nil, &ManagementRecoveryOutcomeError{Status: "NOT_COMMITTED", OpID: recoveryOperation.OpID, Err: errPersist}
				}
				if errVerify != nil {
					return nil, &ManagementRecoveryOutcomeError{Status: "UNKNOWN", OpID: recoveryOperation.OpID, Err: errVerify}
				}
				return nil, &ManagementRecoveryOutcomeError{Status: "UNKNOWN", OpID: recoveryOperation.OpID, Err: errPersist}
			}
			return nil, fmt.Errorf("failed to persist Disabled state: %w", errPersist)
		}
		if isRecovery {
			recoveryStore := m.store.(ManagementRecoveryStore)
			recoveryOperation.State = ManagementRecoveryPrepared
			state, errCommit := recoveryStore.CommitManagementRecovery(ctx, authClone, recoveryOperation)
			verified, errVerify := recoveryStore.VerifyManagementRecovery(ctx, authClone, recoveryOperation)
			if errVerify != nil || verified != ManagementRecoveryCommitted {
				m.mu.Unlock()
				if errVerify == nil && verified == ManagementRecoveryPrepared {
					return nil, &ManagementRecoveryOutcomeError{Status: "NOT_COMMITTED", OpID: recoveryOperation.OpID, Err: errCommit}
				}
				return nil, &ManagementRecoveryOutcomeError{Status: "UNKNOWN", OpID: recoveryOperation.OpID, Err: errVerify}
			}
			if errCommit != nil || state != ManagementRecoveryCommitted {
				// The durable COMMITTED record is authoritative even when the
				// response from the final write was lost.
			}
			if authClone.Metadata == nil {
				authClone.Metadata = make(map[string]any)
			}
			authClone.Metadata[RecoveryStateKey] = string(ManagementRecoveryCommitted)
		}
	}
	m.auths[auth.ID] = authClone
	m.mu.Unlock()
	if !shouldDeferAPIKeyModelAliasRebuild(ctx) {
		m.rebuildAPIKeyModelAliasFromRuntimeConfig()
	}
	if m.scheduler != nil {
		m.scheduler.upsertAuth(authClone.Clone())
	}
	m.structuralEpoch.Add(1)
	m.queueRefreshReschedule(auth.ID)
	if !persistMetaMint && !isDisabledUpdate {
		if errPersist := m.persist(ctx, auth); errPersist != nil {
			// Non-critical persist failure: log but allow update to succeed for backward compatibility.
			log.Warnf("persist failed for non-critical update on %s: %v", auth.ID, errPersist)
		}
		// Preserve the ordinary update hook/return contract for store enrichment.
		authClone = auth.Clone()
	}
	m.hook.OnAuthUpdated(ctx, authClone.Clone())
	if cooldownStateChanged {
		m.persistCooldownStates(context.Background())
	}
	return authClone.Clone(), nil
}

// Remove deletes an auth from runtime state without persisting.
// Disk and token-store deletion must be handled by the caller.
func (m *Manager) Remove(ctx context.Context, id string) {
	if m == nil {
		return
	}
	id = strings.TrimSpace(id)
	if id == "" {
		return
	}
	if m.poolGuard != nil {
		m.poolGuard.mu.Lock()
		defer m.poolGuard.mu.Unlock()
	}
	m.mu.Lock()
	existing := m.auths[id]
	if existing == nil {
		m.mu.Unlock()
		return
	}
	if m.poolGuard != nil {
		incoming := existing.Clone()
		incoming.Metadata = nil
		incoming.Attributes = nil
		if err := m.invalidatePoolReplacement(ctx, existing, incoming); err != nil {
			m.mu.Unlock()
			return
		}
	}
	provider := strings.TrimSpace(existing.Provider)
	delete(m.auths, id)
	if m.modelPoolOffsets != nil {
		delete(m.modelPoolOffsets, id)
	}
	for sessionID, sessionAuths := range m.homeRuntimeAuths {
		if sessionAuths == nil {
			continue
		}
		delete(sessionAuths, id)
		if len(sessionAuths) == 0 {
			delete(m.homeRuntimeAuths, sessionID)
		}
	}
	if m.authEpochs == nil {
		m.authEpochs = make(map[string]uint64)
	}
	if existing.RegistrationEpoch > m.authEpochs[id] {
		m.authEpochs[id] = existing.RegistrationEpoch
	}
	m.authEpochs[id]++
	tombstoneEpoch := m.authEpochs[id]
	m.mu.Unlock()

	if !shouldDeferAPIKeyModelAliasRebuild(ctx) {
		m.rebuildAPIKeyModelAliasFromRuntimeConfig()
	}
	if m.scheduler != nil {
		m.scheduler.RecordRemovalTombstone(id, tombstoneEpoch)
	}
	m.structuralEpoch.Add(1)
	m.queueRefreshUnschedule(id)
	m.invalidateSessionAffinity(id)

	if provider != "" {
		if exec, ok := m.Executor(provider); ok && exec != nil {
			if closer, okCloser := exec.(ExecutionSessionCloser); okCloser {
				closer.CloseExecutionSession(CloseAllExecutionSessionsID)
			}
		}
	}
	m.persistCooldownStates(context.Background())
}

func (m *Manager) invalidateSessionAffinity(authID string) {
	if m == nil || authID == "" {
		return
	}
	sel := m.Selector()
	if invalidator, ok := sel.(interface{ InvalidateAuth(string) }); ok && invalidator != nil {
		invalidator.InvalidateAuth(authID)
	}
}

// Load resets manager state from the backing store.
func (m *Manager) Load(ctx context.Context) error {
	if m.poolGuard != nil {
		m.poolGuard.mu.Lock()
		defer m.poolGuard.mu.Unlock()
	}
	m.mu.Lock()
	if m.store == nil {
		m.mu.Unlock()
		return nil
	}
	items, err := m.store.List(ctx)
	if err != nil {
		m.mu.Unlock()
		return err
	}
	previousAuths := m.auths
	if m.poolGuard != nil {
		incoming := make(map[string]*Auth)
		for _, item := range items {
			if item != nil {
				incoming[item.ID] = item
			}
		}
		for id, existing := range previousAuths {
			replacement := incoming[id]
			if replacement == nil {
				replacement = &Auth{}
			}
			if err := m.invalidatePoolReplacement(ctx, existing, replacement); err != nil {
				m.mu.Unlock()
				return err
			}
		}
	}
	m.auths = make(map[string]*Auth, len(items))
	if m.authEpochs == nil {
		m.authEpochs = make(map[string]uint64, len(items))
	}
	for _, auth := range items {
		if auth == nil || auth.ID == "" {
			continue
		}
		NormalizeCredentialMetadata(auth.Metadata)
		if m.poolGuard != nil {
			ApplyPersistentManagementIsolation(auth)
			if old := previousAuths[auth.ID]; old != nil && ManagementIsolation(old) {
				auth.Metadata[ManagementDisabledKey] = true
				quarantinePoolAuth(auth)
			}
		}
		if errWeight := ValidateAuthWeight(auth); errWeight != nil {
			continue
		}
		if m.poolGuard != nil {
			if _, err := m.poolGrant(auth, firstPoolGrantModel(m, auth), nil); err != nil {
				quarantinePoolAuth(auth)
			}
		}
		auth.EnsureIndex()
		m.authEpochs[auth.ID] = max(m.authEpochs[auth.ID], auth.RegistrationEpoch) + 1
		auth.RegistrationEpoch = m.authEpochs[auth.ID]
		auth.Generation = 1
		if recoveryGeneration, okRecovery := PersistedRecoveryGeneration(auth); okRecovery {
			auth.Generation = recoveryGeneration
		}
		m.auths[auth.ID] = auth.Clone()
	}

	type removalTombstone struct {
		id    string
		epoch uint64
	}
	var removedTombstones []removalTombstone
	for prevID := range previousAuths {
		if _, exists := m.auths[prevID]; !exists {
			m.authEpochs[prevID]++
			removedTombstones = append(removedTombstones, removalTombstone{
				id:    prevID,
				epoch: m.authEpochs[prevID],
			})
		}
	}

	cfg, _ := m.runtimeConfig.Load().(*internalconfig.Config)
	if cfg == nil {
		cfg = &internalconfig.Config{}
	}
	m.rebuildAPIKeyModelAliasLocked(cfg)
	m.mu.Unlock()

	if m.scheduler != nil {
		for _, rt := range removedTombstones {
			m.scheduler.RecordRemovalTombstone(rt.id, rt.epoch)
		}
	}
	m.structuralEpoch.Add(1)
	m.syncScheduler()
	return nil
}

type authPersistLock struct {
	mu             sync.Mutex
	lastEpoch      uint64
	lastGeneration uint64
}

func (m *Manager) persist(ctx context.Context, auth *Auth) error {
	if m.store == nil || auth == nil {
		return nil
	}
	if errWeight := ValidateAuthWeight(auth); errWeight != nil {
		return fmt.Errorf("persist auth: %w", errWeight)
	}
	if IsConfigAPIKeyAuth(auth) {
		return nil
	}
	if auth.Attributes != nil {
		if v := strings.ToLower(strings.TrimSpace(auth.Attributes["runtime_only"])); v == "true" {
			return nil
		}
	}
	if IsPluginVirtualAuth(auth) {
		return nil
	}
	// Skip persistence when metadata is absent (e.g., runtime-only auths).
	if auth.Metadata == nil {
		return nil
	}

	lockVal, _ := m.persistLocks.LoadOrStore(auth.ID, &authPersistLock{})
	pLock, _ := lockVal.(*authPersistLock)
	if pLock != nil {
		pLock.mu.Lock()
		defer pLock.mu.Unlock()
		if auth.RegistrationEpoch < pLock.lastEpoch || (auth.RegistrationEpoch == pLock.lastEpoch && auth.Generation < pLock.lastGeneration) {
			return nil
		}
		pLock.lastEpoch = auth.RegistrationEpoch
		pLock.lastGeneration = auth.Generation
		if shouldSkipPersist(ctx) {
			return nil
		}
		_, err := m.store.Save(ctx, auth)
		return err
	}

	if shouldSkipPersist(ctx) {
		return nil
	}
	_, err := m.store.Save(ctx, auth)
	return err
}
