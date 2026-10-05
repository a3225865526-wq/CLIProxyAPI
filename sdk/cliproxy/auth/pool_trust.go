package auth

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"sort"
)

const (
	PoolTrustPending = "pending"
	PoolTrustTrusted = "trusted"
	PoolTrustRevoked = "revoked"
)

// The generation is an accepted 1A journal revision, not a separate counter.
type PoolTrustRecord struct {
	AuthID               string `json:"auth_id"`
	Provider             string `json:"provider"`
	CredentialDigest     string `json:"credential_digest"`
	State                string `json:"state"`
	AuthorizationVersion uint64 `json:"authorization_version"`
	Generation           uint64 `json:"generation"`
}

type PoolIdentityExpectation struct {
	AuthID           string `json:"auth_id"`
	Provider         string `json:"provider"`
	CredentialDigest string `json:"credential_digest"`
	Generation       uint64 `json:"generation"`
}

type PoolPromotion struct {
	ExpectedRevision uint64                    `json:"expected_revision"`
	Identities       []PoolIdentityExpectation `json:"identities"`
}

type PoolRevocation struct {
	ExpectedRevision uint64                  `json:"expected_revision"`
	Identity         PoolIdentityExpectation `json:"identity"`
}

func validPoolTrust(checkpoint poolCheckpoint) bool {
	if len(checkpoint.Trust) > 1024 {
		return false
	}
	seen := make(map[string]bool)
	for _, item := range checkpoint.Trust {
		digest, err := hex.DecodeString(item.CredentialDigest)
		if item.AuthID == "" || item.Provider == "" || seen[item.AuthID] || err != nil || len(digest) != 32 || item.Generation == 0 || item.Generation > checkpoint.Revision || item.AuthorizationVersion == 0 || item.AuthorizationVersion > checkpoint.Revision {
			return false
		}
		if item.State != PoolTrustTrusted && item.State != PoolTrustPending && item.State != PoolTrustRevoked {
			return false
		}
		if item.State == PoolTrustTrusted && item.AuthorizationVersion != checkpoint.Revision {
			return false
		}
		seen[item.AuthID] = true
	}
	return true
}

func pendingPoolTrust(previous []PoolTrustRecord, revision uint64) []PoolTrustRecord {
	result := append([]PoolTrustRecord(nil), previous...)
	for i := range result {
		if result[i].State == PoolTrustTrusted {
			result[i].State = PoolTrustPending
			result[i].Generation = revision
		}
	}
	return result
}

func (guard *poolGuard) trusted(auth *Auth, revision uint64) (PoolTrustRecord, bool) {
	guard.journalMu.Lock()
	defer guard.journalMu.Unlock()
	item, ok := guard.trust[auth.ID]
	return item, ok && item.State == PoolTrustTrusted && item.AuthorizationVersion == revision && item.Provider == auth.Provider && item.CredentialDigest == PoolCredentialDigest(auth)
}

// PoolTrustSnapshot reports non-secret security records, independently of health.
func (m *Manager) PoolTrustSnapshot() (uint64, []PoolTrustRecord, error) {
	if m == nil || m.poolGuard == nil {
		return 0, nil, ErrPoolGuard
	}
	m.poolGuard.mu.Lock()
	defer m.poolGuard.mu.Unlock()
	record, err := m.poolGrants()
	if err != nil {
		return 0, nil, err
	}
	m.poolGuard.journalMu.Lock()
	defer m.poolGuard.journalMu.Unlock()
	items := make([]PoolTrustRecord, 0, len(m.poolGuard.trust))
	for _, item := range m.poolGuard.trust {
		items = append(items, item)
	}
	sort.Slice(items, func(i, j int) bool { return items[i].AuthID < items[j].AuthID })
	return record.Revision, items, nil
}

// PoolPendingIdentities reports the loaded codex OAuth identities that do not
// yet have a trusted record bound to their current credential digest, together
// with the exact credential digest promotion must present. Without this the
// first promotion of an identity is unachievable for an operator: the promote
// command requires the digest, and the digest is only well-defined after the
// service layer finished preparing the loaded credential. The values are
// SHA-256 digests over non-secret references and are only reachable behind
// the authenticated management plane.
func (m *Manager) PoolPendingIdentities() ([]PoolIdentityExpectation, error) {
	if m == nil || m.poolGuard == nil {
		return nil, ErrPoolGuard
	}
	// Sequential, never nested: poolGrants takes the journal lock internally
	// (mirroring PoolTrustSnapshot), then m.mu → journalMu matches the
	// selection-path lock order.
	if _, err := m.poolGrants(); err != nil {
		return nil, err
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	m.poolGuard.journalMu.Lock()
	defer m.poolGuard.journalMu.Unlock()
	items := make([]PoolIdentityExpectation, 0)
	for _, auth := range m.auths {
		if auth == nil || auth.Provider != "codex" || auth.AuthKind() != AuthKindOAuth {
			continue
		}
		digest := PoolCredentialDigest(auth)
		if digest == "" {
			continue
		}
		if trust, ok := m.poolGuard.trust[auth.ID]; ok && trust.State == PoolTrustTrusted && trust.CredentialDigest == digest {
			continue
		}
		items = append(items, PoolIdentityExpectation{
			AuthID:           auth.ID,
			Provider:         auth.Provider,
			CredentialDigest: digest,
			Generation:       m.poolGuard.trust[auth.ID].Generation,
		})
	}
	sort.Slice(items, func(i, j int) bool { return items[i].AuthID < items[j].AuthID })
	return items, nil
}

// Promotion deliberately names every identity trusted in the new snapshot.
// Advancing the global authorization version never implicitly reapproves others.
func (m *Manager) PromotePoolIdentities(ctx context.Context, command PoolPromotion) error {
	if m == nil || m.poolGuard == nil || len(command.Identities) == 0 {
		return ErrPoolGuard
	}
	guard := m.poolGuard
	guard.mu.Lock()
	defer guard.mu.Unlock()
	if _, err := m.poolGrants(); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.commitPoolTrust(ctx, command.ExpectedRevision, command.Identities, PoolTrustTrusted)
}

func (m *Manager) RevokePoolIdentity(ctx context.Context, command PoolRevocation) error {
	if m == nil || m.poolGuard == nil {
		return ErrPoolGuard
	}
	guard := m.poolGuard
	guard.mu.Lock()
	defer guard.mu.Unlock()
	if _, err := m.poolGrants(); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.commitPoolTrust(ctx, command.ExpectedRevision, []PoolIdentityExpectation{command.Identity}, PoolTrustRevoked)
}

// Caller holds guard.mu then manager.mu. OS locking spans both durable writes
// and the CAS, so concurrent managers cannot publish an obsolete operation.
func (m *Manager) commitPoolTrust(ctx context.Context, expected uint64, identities []PoolIdentityExpectation, state string) (resultErr error) {
	guard := m.poolGuard
	guard.journalMu.Lock()
	defer guard.journalMu.Unlock()
	file, err := guard.openPoolCheckpoint()
	if err != nil {
		return err
	}
	defer func() {
		unlockPoolCheckpoint(file)
		if file.Close() != nil {
			guard.faulted.Store(true)
			resultErr = ErrPoolGuard
		}
	}()
	floor, size, err := guard.readPoolCheckpoint(file)
	if err != nil {
		return err
	}
	record, err := guard.grants()
	if err != nil || expected == 0 || expected != floor.Revision || record.Revision != expected || poolRecordDigest(record) != floor.Digest || expected == math.MaxUint64 {
		return ErrPoolGuard
	}
	previous := make(map[string]PoolTrustRecord)
	for _, item := range floor.Trust {
		previous[item.AuthID] = item
	}
	seen := make(map[string]bool)
	for _, identity := range identities {
		auth := m.auths[identity.AuthID]
		old := previous[identity.AuthID]
		if auth == nil || auth.AuthKind() != AuthKindOAuth || seen[identity.AuthID] || auth.Provider != identity.Provider || PoolCredentialDigest(auth) != identity.CredentialDigest || old.Generation != identity.Generation {
			return ErrPoolGuard
		}
		seen[identity.AuthID] = true
		if state == PoolTrustTrusted {
			if auth.Provider != "codex" {
				return ErrPoolGuard
			}
			candidate := auth.Clone()
			candidate.Disabled = false
			candidate.Status = StatusActive
			if _, err := m.matchPoolGrant(record, candidate, firstGrantModel(record, identity.AuthID), nil); err != nil {
				return err
			}
		}
	}
	nextRevision := expected + 1
	nextTrust := pendingPoolTrust(floor.Trust, nextRevision)
	nextByID := make(map[string]PoolTrustRecord)
	for _, item := range nextTrust {
		nextByID[item.AuthID] = item
	}
	for _, identity := range identities {
		nextByID[identity.AuthID] = PoolTrustRecord{AuthID: identity.AuthID, Provider: identity.Provider, CredentialDigest: identity.CredentialDigest, State: state, AuthorizationVersion: nextRevision, Generation: nextRevision}
	}
	nextTrust = nil
	for _, item := range nextByID {
		nextTrust = append(nextTrust, item)
	}
	sort.Slice(nextTrust, func(i, j int) bool { return nextTrust[i].AuthID < nextTrust[j].AuthID })
	record.Revision = nextRevision
	next := poolCheckpoint{GuardVersion: PoolGuardVersion, ExecutorID: guard.executorID, Revision: nextRevision, Digest: poolRecordDigest(record), Trust: nextTrust}
	if !validPoolTrust(next) {
		return ErrPoolGuard
	}
	// An enabled credential on disk still has no authority without the journal.
	// Do not publish it in manager memory until both security writes succeed.
	if state == PoolTrustTrusted {
		for _, identity := range identities {
			candidate := m.auths[identity.AuthID].Clone()
			candidate.Disabled = false
			candidate.Status = StatusActive
			if candidate.Metadata != nil {
				candidate.Metadata["disabled"] = false
			}
			if err := m.persist(ctx, candidate); err != nil {
				return err
			}
			// A store may enrich credential attributes; that requires a new proposal.
			if PoolCredentialDigest(candidate) != identity.CredentialDigest {
				return ErrPoolGuard
			}
		}
	}
	if err := writePoolPolicy(guard.file, record); err != nil {
		guard.faulted.Store(true)
		guard.cancelPoolLeases(ErrPoolGuard)
		return err
	}
	if err := guard.appendPoolCheckpoint(file, size, next); err != nil {
		guard.faulted.Store(true)
		guard.cancelPoolLeases(ErrPoolGuard)
		return err
	}
	guard.installPoolCheckpoint(next)
	// A global revision change invalidates every old lease, conservatively.
	for _, lease := range guard.leases {
		reason := error(ErrPoolGuard)
		if state == PoolTrustRevoked && seen[lease.AuthID] {
			reason = ErrAccountRevoked
		}
		lease.cancel(reason)
	}
	if state == PoolTrustTrusted {
		for _, identity := range identities {
			installed := m.auths[identity.AuthID].Clone()
			installed.Disabled = false
			installed.Status = StatusActive
			installed.Generation++
			if installed.Metadata != nil {
				installed.Metadata["disabled"] = false
			}
			m.auths[identity.AuthID] = installed
		}
	}
	return nil
}

func firstGrantModel(record *PoolGrantFile, id string) string {
	for _, grant := range record.Grants {
		if grant.AuthID == id && len(grant.Models) > 0 {
			return grant.Models[0]
		}
	}
	return ""
}

func writePoolPolicy(path string, record *PoolGrantFile) error {
	data, err := json.Marshal(record)
	if err != nil {
		return ErrPoolGuard
	}
	file, err := os.CreateTemp(filepath.Dir(path), ".pool-policy-*")
	if err != nil {
		return ErrPoolGuard
	}
	name := file.Name()
	defer os.Remove(name)
	if file.Chmod(0600) != nil {
		_ = file.Close()
		return ErrPoolGuard
	}
	count, writeErr := file.Write(data)
	syncErr := file.Sync()
	closeErr := file.Close()
	if writeErr != nil || count != len(data) || syncErr != nil || closeErr != nil {
		return ErrPoolGuard
	}
	if err := replacePoolPolicy(name, path); err != nil {
		return ErrPoolGuard
	}
	return nil
}

// A credential replacement burns its former trust even if the old bytes return.
// Caller holds guard.mu and manager.mu; ordinary pause does not change trust.
func (m *Manager) invalidatePoolReplacement(ctx context.Context, existing, incoming *Auth) error {
	if m.poolGuard == nil || existing == nil || PoolCredentialDigest(existing) == PoolCredentialDigest(incoming) {
		return nil
	}
	guard := m.poolGuard
	guard.journalMu.Lock()
	trust, exists := guard.trust[existing.ID]
	revision := guard.lastRevision
	guard.journalMu.Unlock()
	if !exists || trust.State != PoolTrustTrusted {
		return nil
	}
	command := PoolIdentityExpectation{AuthID: existing.ID, Provider: existing.Provider, CredentialDigest: PoolCredentialDigest(existing), Generation: trust.Generation}
	if err := m.commitPoolTrust(ctx, revision, []PoolIdentityExpectation{command}, PoolTrustPending); err != nil {
		guard.faulted.Store(true)
		guard.cancelPoolLeases(ErrPoolGuard)
		return err
	}
	return nil
}
