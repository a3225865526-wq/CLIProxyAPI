package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/google/uuid"
)

const (
	ManagementDisabledKey = "management_disabled"
	RecoveryOpIDKey       = "management_recovery_op_id"
	RecoveryGenerationKey = "management_recovery_generation"
	RecoveryRevisionKey   = "management_recovery_revision"
	RecoveryStateKey      = "management_recovery_state"
)

// PersistedRecoveryGeneration returns the generation carried by a complete
// committed recovery marker. Other states are never trusted as runtime state.
func PersistedRecoveryGeneration(a *Auth) (uint64, bool) {
	if a == nil || a.Metadata == nil || a.Metadata[RecoveryStateKey] != string(ManagementRecoveryCommitted) {
		return 0, false
	}
	switch value := a.Metadata[RecoveryGenerationKey].(type) {
	case uint64:
		return value, value != 0
	case float64:
		if value > 0 && value == float64(uint64(value)) {
			return uint64(value), true
		}
	case json.Number:
		parsed, errParse := value.Int64()
		if errParse == nil && parsed > 0 {
			return uint64(parsed), true
		}
	}
	return 0, false
}

// PersistentAuthDisabled distinguishes ordinary legacy files from pool files.
// Unknown pool state and malformed flags require explicit management recovery.
// It normalizes only in-memory metadata; reading never rewrites the file.
func PersistentAuthDisabled(metadata map[string]any) bool {
	if metadata == nil {
		return true
	}
	disabled, valid := metadata["disabled"].(bool)
	_, present := metadata["disabled"]
	unknown := !valid && (present || strings.TrimSpace(os.Getenv("CLEARAPI_POOL_ROLE")) != "")
	if unknown {
		disabled = true
		metadata[ManagementDisabledKey] = true
	} else if _, present := metadata[ManagementDisabledKey]; !present {
		metadata[ManagementDisabledKey] = disabled
	}
	return disabled || ManagementIsolation(&Auth{Metadata: metadata})
}

type managementStatusKey struct{}
type managementStatusExpectation struct {
	id         string
	digest     string
	generation uint64
	epoch      uint64
	revision   uint64
}

type managementRecoveryPlan struct {
	opID     string
	expected managementStatusExpectation
}
type managementRecoveryContextKey struct{}

// Caller holds Manager.mu, serializing this proof with management mutations.
func (m *Manager) staleRecoveryIsolationSnapshot(ctx context.Context, existing, incoming *Auth) bool {
	if m.poolGuard == nil || !shouldSkipPersist(ctx) || incoming.Generation != 0 ||
		!incoming.Disabled || existing.Disabled || ManagementIsolation(existing) ||
		incoming.Provider != existing.Provider || PoolCredentialDigest(incoming) != PoolCredentialDigest(existing) {
		return false
	}
	store, supported := m.store.(ManagementRecoveryStore)
	if !supported {
		return false
	}
	var marker struct {
		OpID       string `json:"management_recovery_op_id"`
		Generation uint64 `json:"management_recovery_generation"`
		Revision   uint64 `json:"management_recovery_revision"`
		State      string `json:"management_recovery_state"`
	}
	data, err := json.Marshal(existing.Metadata)
	if err != nil || json.Unmarshal(data, &marker) != nil || marker.State != string(ManagementRecoveryCommitted) {
		return false
	}
	op := ManagementRecoveryOperation{OpID: marker.OpID, AuthID: existing.ID,
		CredentialDigest: PoolCredentialDigest(existing), Generation: marker.Generation,
		Revision: marker.Revision, State: ManagementRecoveryPrepared}
	state, err := store.VerifyManagementRecovery(ctx, existing.Clone(), op)
	return err == nil && state == ManagementRecoveryCommitted
}

// ManagementIsolation is independent of trust. Malformed flags deny admission.
func ManagementIsolation(a *Auth) bool {
	if a == nil {
		return true
	}
	value, present := a.Metadata[ManagementDisabledKey]
	if !present {
		return false
	}
	disabled, valid := value.(bool)
	return !valid || disabled
}

// ApplyPersistentManagementIsolation conservatively migrates legacy isolated
// files. Fresh admission quarantine is explicitly marked false by Register.
func ApplyPersistentManagementIsolation(a *Auth) {
	if a == nil {
		return
	}
	if a.Metadata == nil {
		a.Metadata = make(map[string]any)
	}
	if _, present := a.Metadata[ManagementDisabledKey]; !present {
		a.Metadata[ManagementDisabledKey] = a.Disabled || a.Status == StatusDisabled
	}
	if ManagementIsolation(a) {
		quarantinePoolAuth(a)
	}
}

// UpdateManagementStatus is the explicitly authorized management mutation.
// The caller's snapshot is rechecked inside the existing identity locks.
func (m *Manager) UpdateManagementStatus(ctx context.Context, snapshot *Auth, disabled bool) (*Auth, error) {
	if snapshot == nil {
		return nil, ErrPoolGuard
	}
	if ctx == nil {
		ctx = context.Background()
	}
	expected := managementStatusExpectation{snapshot.ID, PoolCredentialDigest(snapshot), snapshot.Generation, snapshot.RegistrationEpoch, 0}
	candidate := snapshot.Clone()
	if candidate.Metadata == nil {
		candidate.Metadata = make(map[string]any)
	}
	candidate.Metadata[ManagementDisabledKey] = disabled
	candidate.Metadata["disabled"] = disabled
	candidate.Disabled = disabled
	if disabled {
		candidate.Status = StatusDisabled
	} else {
		candidate.Status = StatusActive
	}
	ctx = context.WithValue(ctx, managementStatusKey{}, expected)
	if m.poolGuard == nil {
		return m.Update(ctx, candidate)
	}
	if !disabled {
		_, supported := m.store.(ManagementRecoveryStore)
		if !supported {
			return nil, &ManagementRecoveryOutcomeError{Status: "NOT_COMMITTED", Err: fmt.Errorf("backend does not support FileStore WAL recovery")}
		}
		if revision, _, errRevision := m.PoolTrustSnapshot(); errRevision != nil {
			return nil, &ManagementRecoveryOutcomeError{Status: "NOT_COMMITTED", Err: errRevision}
		} else {
			expected.revision = revision
			ctx = context.WithValue(ctx, managementStatusKey{}, expected)
		}
		ctx = context.WithValue(ctx, managementRecoveryContextKey{}, managementRecoveryPlan{opID: uuid.NewString(), expected: expected})
	}
	return m.Update(ctx, candidate)
}
