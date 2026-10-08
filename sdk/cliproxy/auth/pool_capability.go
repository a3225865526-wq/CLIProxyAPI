package auth

import (
	"context"
	"encoding/hex"
	"math"
	"sort"
	"strings"

	log "github.com/sirupsen/logrus"
)

// STEP 3 model capability admission. A trusted account is not a trusted model:
// every account×model pair needs an explicit, persisted capability record on
// top of the operator grant floor. Unknown means deny. Records bind the 1A
// credential digest and the 1B trust generation, so credential replacement or
// re-promotion invalidates them without any extra machinery.
const (
	PoolCapabilityVerified = "verified"
	PoolCapabilityRevoked  = "revoked"
)

// Structured denial reasons for observability. External responses stay coarse
// (pool_admission_required) so the ledger's internals do not leak to callers.
const (
	PoolDenialAccountUntrusted = "account_untrusted"
	PoolDenialModelUnverified  = "model_unverified"
	PoolDenialModelNotAllowed  = "model_not_allowed"
	PoolDenialModelRevoked     = "model_capability_revoked"
	PoolDenialStaleCapability  = "stale_capability"
)

// PoolModelCapability is one account×model admission record. Model is stored in
// canonical form; matching is exact on the canonical key with no prefix,
// substring, or case folding. IdentityVersion reports the credential identity
// schema of the bound digest (0 = legacy v1, fail-closed by digest mismatch).
type PoolModelCapability struct {
	AuthID           string `json:"auth_id"`
	Provider         string `json:"provider"`
	CredentialDigest string `json:"credential_digest"`
	Model            string `json:"model"`
	State            string `json:"state"`
	Generation       uint64 `json:"generation"`
	IdentityVersion  int    `json:"identity_version,omitempty"`
}

type PoolModelGrant struct {
	ExpectedRevision uint64                  `json:"expected_revision"`
	Identity         PoolIdentityExpectation `json:"identity"`
	Model            string                  `json:"model"`
}

type PoolModelRevoke struct {
	ExpectedRevision uint64                  `json:"expected_revision"`
	Identity         PoolIdentityExpectation `json:"identity"`
	Model            string                  `json:"model"`
}

// canonicalPoolModel is the admission identity of a model: the project canonical
// key (trimmed, thinking suffix stripped) with a strict length bound. There is
// deliberately no lowercasing, wildcard, prefix, or substring semantics.
func canonicalPoolModel(model string) string {
	key := canonicalModelKey(model)
	if key == "" || len(key) > 128 || strings.ContainsAny(key, " \t\r\n\x00") {
		return ""
	}
	return key
}

func validPoolCapabilities(record *PoolGrantFile) bool {
	if len(record.Capabilities) > 4096 {
		return false
	}
	seen := make(map[string]struct{}, len(record.Capabilities))
	for _, item := range record.Capabilities {
		digest, err := hex.DecodeString(item.CredentialDigest)
		if item.AuthID == "" || item.Provider == "" || err != nil || len(digest) != 32 {
			return false
		}
		if item.IdentityVersion != 0 && item.IdentityVersion != CredentialSecurityIdentityVersion {
			return false
		}
		if item.Model == "" || item.Model != canonicalPoolModel(item.Model) {
			return false
		}
		if item.State != PoolCapabilityVerified && item.State != PoolCapabilityRevoked || item.Generation == 0 {
			return false
		}
		key := item.AuthID + "\x00" + item.Model
		if _, duplicate := seen[key]; duplicate {
			return false
		}
		seen[key] = struct{}{}
	}
	return true
}

// poolModelAdmitted reports whether the canonical form of model is explicitly
// admitted for this account under the current trust state. The returned reason
// is observability only; the error is always the coarse ErrPoolGuard.
func (m *Manager) poolModelAdmitted(record *PoolGrantFile, auth *Auth, model string) (string, error) {
	if m == nil || m.poolGuard == nil {
		return "", nil
	}
	key := canonicalPoolModel(model)
	if key == "" {
		return PoolDenialModelNotAllowed, ErrPoolGuard
	}
	guard := m.poolGuard
	guard.journalMu.Lock()
	trust, ok := guard.trust[auth.ID]
	guard.journalMu.Unlock()
	digest := PoolCredentialDigest(auth)
	if !ok || trust.State != PoolTrustTrusted || trust.AuthorizationVersion != record.Revision || trust.Provider != auth.Provider || trust.CredentialDigest != digest {
		return PoolDenialAccountUntrusted, ErrPoolGuard
	}
	for i := range record.Capabilities {
		item := &record.Capabilities[i]
		if item.AuthID != auth.ID || item.Model != key {
			continue
		}
		if item.State == PoolCapabilityRevoked {
			return PoolDenialModelRevoked, ErrPoolGuard
		}
		if item.Provider != auth.Provider || item.CredentialDigest != digest || item.Generation != trust.Generation {
			return PoolDenialStaleCapability, ErrPoolGuard
		}
		return "", nil
	}
	return PoolDenialModelUnverified, ErrPoolGuard
}

// poolModelCheck combines the operator grant floor with the capability ledger
// for one candidate model. Callers may pass a record they already loaded to
// avoid rereading the policy file per candidate.
func (m *Manager) poolModelCheck(record *PoolGrantFile, auth *Auth, model string, capabilities []string) error {
	if _, err := m.matchPoolGrant(record, auth, model, capabilities); err != nil {
		return err
	}
	_, err := m.poolModelAdmitted(record, auth, model)
	return err
}

// poolLogModelDecision records the structured admission decision. It never
// logs credential contents; the credential reference is the SHA-256 digest.
func poolLogModelDecision(ctx context.Context, auth *Auth, requestedModel, model string, allowed bool, reason string, capabilityRevision, trustGeneration uint64) {
	entry := logEntryWithRequestID(ctx)
	if !entry.Logger.IsLevelEnabled(log.InfoLevel) {
		return
	}
	decision := "deny"
	level := log.WarnLevel
	if allowed {
		decision = "allow"
		level = log.DebugLevel
	}
	entry.WithFields(log.Fields{
		"pool_model_decision":     decision,
		"pool_denial_reason":      reason,
		"pool_account":            auth.ID,
		"pool_credential_ref":     PoolCredentialDigest(auth),
		"pool_requested_model":    requestedModel,
		"pool_canonical_model":    canonicalPoolModel(model),
		"pool_capability_version": capabilityRevision,
		"pool_trust_generation":   trustGeneration,
	}).Log(level, "pool model capability admission")
}

// GrantPoolModelCapability explicitly admits one account×model pair. The
// command is stale-write protected by the shared policy Revision CAS and the
// identity's current trust generation; granting requires a trusted identity.
func (m *Manager) GrantPoolModelCapability(ctx context.Context, command PoolModelGrant) error {
	return m.commitPoolModelCapability(ctx, command, PoolCapabilityVerified)
}

// RevokePoolModelCapability revokes one account×model pair. Other admitted
// models of the same account keep working; the account trust state is untouched.
func (m *Manager) RevokePoolModelCapability(ctx context.Context, command PoolModelRevoke) error {
	return m.commitPoolModelCapability(ctx, PoolModelGrant(command), PoolCapabilityRevoked)
}

func (m *Manager) commitPoolModelCapability(ctx context.Context, command PoolModelGrant, state string) (resultErr error) {
	if m == nil || m.poolGuard == nil || m.poolGuard.role != "service" {
		return ErrPoolGuard
	}
	guard := m.poolGuard
	defer func() {
		if resultErr == nil {
			resultErr = m.syncPoolRegistry(ctx)
		}
	}()
	guard.mu.Lock()
	defer guard.mu.Unlock()
	if _, err := m.poolGrants(); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.commitPoolModelCapabilityLocked(ctx, command, state)
}

// Caller holds guard.mu then manager.mu; the lock order, CAS, and fail-closed
// write discipline are identical to commitPoolTrust. A capability commit
// re-anchors still-trusted identities to the new policy revision without
// changing their trust state or generation, so no capability is implicitly
// widened and no trust is implicitly restored.
func (m *Manager) commitPoolModelCapabilityLocked(ctx context.Context, command PoolModelGrant, state string) (resultErr error) {
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
	if err != nil || command.ExpectedRevision == 0 || command.ExpectedRevision != floor.Revision || record.Revision != command.ExpectedRevision || poolRecordDigest(record) != floor.Digest || command.ExpectedRevision == math.MaxUint64 {
		return ErrPoolGuard
	}
	auth := m.auths[command.Identity.AuthID]
	if auth == nil || auth.AuthKind() != AuthKindOAuth || auth.Provider != command.Identity.Provider || PoolCredentialDigest(auth) != command.Identity.CredentialDigest {
		return ErrPoolGuard
	}
	var trust *PoolTrustRecord
	for i := range floor.Trust {
		if floor.Trust[i].AuthID == command.Identity.AuthID {
			trust = &floor.Trust[i]
			break
		}
	}
	if trust == nil || trust.Generation != command.Identity.Generation || trust.CredentialDigest != command.Identity.CredentialDigest || trust.Provider != command.Identity.Provider {
		return ErrPoolGuard
	}
	if state == PoolCapabilityVerified && trust.State != PoolTrustTrusted {
		return ErrPoolGuard
	}
	if state == PoolCapabilityRevoked && trust.State != PoolTrustTrusted && trust.State != PoolTrustPending {
		return ErrPoolGuard
	}
	key := canonicalPoolModel(command.Model)
	if key == "" {
		return ErrPoolGuard
	}
	nextCapabilities := make([]PoolModelCapability, 0, len(record.Capabilities)+1)
	replaced := false
	for _, item := range record.Capabilities {
		if item.AuthID == command.Identity.AuthID && item.Model == key {
			item.State = state
			item.Provider = command.Identity.Provider
			item.CredentialDigest = command.Identity.CredentialDigest
			item.IdentityVersion = CredentialSecurityIdentityVersion
			if state == PoolCapabilityVerified {
				item.Generation = command.Identity.Generation
			}
			replaced = true
		}
		nextCapabilities = append(nextCapabilities, item)
	}
	if !replaced {
		nextCapabilities = append(nextCapabilities, PoolModelCapability{AuthID: command.Identity.AuthID, Provider: command.Identity.Provider, CredentialDigest: command.Identity.CredentialDigest, Model: key, State: state, Generation: command.Identity.Generation, IdentityVersion: CredentialSecurityIdentityVersion})
	}
	sort.Slice(nextCapabilities, func(i, j int) bool {
		if nextCapabilities[i].AuthID != nextCapabilities[j].AuthID {
			return nextCapabilities[i].AuthID < nextCapabilities[j].AuthID
		}
		return nextCapabilities[i].Model < nextCapabilities[j].Model
	})
	record.Capabilities = nextCapabilities
	nextRevision := command.ExpectedRevision + 1
	record.Revision = nextRevision
	nextTrust := make([]PoolTrustRecord, 0, len(floor.Trust))
	for _, item := range floor.Trust {
		if item.State == PoolTrustTrusted {
			item.AuthorizationVersion = nextRevision
		}
		nextTrust = append(nextTrust, item)
	}
	checkpoint := poolCheckpoint{GuardVersion: PoolGuardVersion, ExecutorID: guard.executorID, Revision: nextRevision, Digest: poolRecordDigest(record), Trust: nextTrust}
	if !validPoolTrust(checkpoint) || !validPoolCapabilities(record) {
		return ErrPoolGuard
	}
	if err := writePoolPolicy(guard.file, record); err != nil {
		guard.faulted.Store(true)
		guard.cancelPoolLeases(ErrPoolGuard)
		return err
	}
	if err := guard.appendPoolCheckpoint(file, size, checkpoint); err != nil {
		guard.faulted.Store(true)
		guard.cancelPoolLeases(ErrPoolGuard)
		return err
	}
	guard.installPoolCheckpoint(checkpoint)
	// Any capability change conservatively cancels every lease: a revoked model
	// must not dispatch, and in-flight requests terminate without replay.
	guard.cancelPoolLeases(ErrPoolGuard)
	return nil
}

// PoolModelSnapshot reports the capability ledger and the policy revision it is
// committed under. Records bind their trust generation, so comparing against
// the trust snapshot shows which grants are currently effective.
func (m *Manager) PoolModelSnapshot() (uint64, []PoolModelCapability, error) {
	if m == nil || m.poolGuard == nil {
		return 0, nil, ErrPoolGuard
	}
	m.poolGuard.mu.Lock()
	defer m.poolGuard.mu.Unlock()
	record, err := m.poolGrants()
	if err != nil {
		return 0, nil, err
	}
	items := append([]PoolModelCapability(nil), record.Capabilities...)
	sort.Slice(items, func(i, j int) bool {
		if items[i].AuthID != items[j].AuthID {
			return items[i].AuthID < items[j].AuthID
		}
		return items[i].Model < items[j].Model
	})
	return record.Revision, items, nil
}
