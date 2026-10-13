package auth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"sync"

	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/usage"
)

type accountRevokedError struct{}

func (accountRevokedError) Error() string         { return "account_revoked" }
func (accountRevokedError) StatusCode() int       { return http.StatusForbidden }
func (accountRevokedError) IsRequestScoped() bool { return true }
func (accountRevokedError) IsRequestStop() bool   { return true }

func (accountRevokedError) DirectResponse() bool { return true }
func (accountRevokedError) ResponseBody() []byte {
	return []byte(`{"error":{"message":"account_revoked","type":"security_error","code":"account_revoked"}}`)
}

var ErrAccountRevoked = accountRevokedError{}

// poolAccountingError carries only dispatch evidence, never credentials.
// The original security error remains discoverable with errors.Is/As.
type poolAccountingError struct {
	cause      error
	dispatched bool
	meter      *usage.CodexMetering
}

func (e poolAccountingError) Error() string         { return e.cause.Error() }
func (e poolAccountingError) Unwrap() error         { return e.cause }
func (e poolAccountingError) DirectResponse() bool  { return true }
func (e poolAccountingError) IsRequestStop() bool   { return true }
func (e poolAccountingError) IsRequestScoped() bool { return true }
func (e poolAccountingError) StatusCode() int       { return http.StatusForbidden }
func (e poolAccountingError) ResponseBody() []byte {
	code := "pool_admission_required"
	if errors.Is(e.cause, ErrAccountRevoked) {
		code = "account_revoked"
	}
	data, _ := json.Marshal(map[string]any{"error": map[string]any{"message": code, "type": "security_error", "code": code, "metadata": map[string]any{"codex_upstream_dispatched": e.dispatched, "codex_metering": e.meter}}})
	return data
}
func poolAccountingTermination(err error, lease *poolLease) error {
	var capacity *poolCapacityRejection
	if errors.As(err, &capacity) {
		return err
	}
	if !errors.Is(err, ErrAccountRevoked) && !errors.Is(err, ErrPoolGuard) {
		return err
	}
	dispatched := false
	if lease != nil {
		lease.manager.poolGuard.mu.RLock()
		dispatched = lease.Dispatched
		lease.manager.poolGuard.mu.RUnlock()
	}
	var meter *usage.CodexMetering
	if lease != nil {
		lease.meterMu.Lock()
		meter = lease.meter
		lease.meterMu.Unlock()
	}
	return poolAccountingError{cause: err, dispatched: dispatched, meter: meter}
}

// PoolInFlight contains no credentials or request bodies. RequestID is a local
// monotonically assigned ID; channel identity remains owned by the website.
type PoolInFlight struct {
	RequestID            uint64 `json:"request_id"`
	AuthID               string `json:"auth_id"`
	Provider             string `json:"provider"`
	ExecutorID           string `json:"executor_id"`
	CredentialDigest     string `json:"credential_digest"`
	AuthorizationVersion uint64 `json:"authorization_version"`
	Generation           uint64 `json:"generation"`
	Dispatched           bool   `json:"dispatched"`
}

type poolLease struct {
	PoolInFlight
	manager            *Manager
	auth               *Auth
	req                cliproxyexecutor.Request
	caps               []string
	requestedModel     string
	attemptID          string
	sessionID          string
	ctx                context.Context
	cancel             context.CancelCauseFunc
	stateMu            sync.Mutex
	retained           bool
	executionEnded     bool
	executionFinalized bool
	transportEnded     bool
	transportEndReason string
	finalEnded         bool
	resourceMu         sync.Mutex
	closeFn            func() error
	resourceClosed     bool
	stopClose          func() bool
	consumeAttempt     bool
	persistent         bool
	connectAuthorized  bool
	payloadAuthorized  bool
	meterMu            sync.Mutex
	meter              *usage.CodexMetering
	receiptID          string
	receiptState       string
	receiptRequestID   string
	receiptFailed      bool
	protocolAdmitted   func() bool
	receiptSSE         bool
	receiptFinal       bool
	previousReceiptID  string
	sseFinalEvent      receiptEvent
}

func (lease *poolLease) observeMetering(m *usage.CodexMetering) {
	lease.meterMu.Lock()
	defer lease.meterMu.Unlock()
	if lease.meter == nil {
		lease.meter = m
	}
}

func (guard *poolGuard) cancelPoolLeases(reason error) {
	for _, lease := range guard.leases {
		lease.cancel(reason)
	}
}

func (m *Manager) PoolInFlightSnapshot() []PoolInFlight {
	if m == nil || m.poolGuard == nil {
		return nil
	}
	m.poolGuard.mu.RLock()
	defer m.poolGuard.mu.RUnlock()
	result := make([]PoolInFlight, 0, len(m.poolGuard.leases))
	for _, lease := range m.poolGuard.leases {
		result = append(result, lease.PoolInFlight)
	}
	return result
}

func (lease *poolLease) closeResource() {
	lease.resourceMu.Lock()
	if lease.resourceClosed {
		lease.resourceMu.Unlock()
		return
	}
	lease.resourceClosed = true
	closeFn := lease.closeFn
	lease.resourceMu.Unlock()
	if closeFn != nil {
		_ = closeFn()
	}
}

func (lease *poolLease) Bind(closeFn func() error) error {
	lease.resourceMu.Lock()
	if closeFn == nil || lease.closeFn != nil || lease.resourceClosed || lease.ctx.Err() != nil {
		lease.resourceMu.Unlock()
		if closeFn != nil {
			_ = closeFn()
		}
		if cause := context.Cause(lease.ctx); cause != nil {
			return cause
		}
		return ErrPoolGuard
	}
	lease.closeFn = closeFn
	lease.resourceMu.Unlock()
	return nil
}

func (lease *poolLease) Retain() {
	lease.stateMu.Lock()
	defer lease.stateMu.Unlock()
	if lease.persistent && !lease.finalEnded && lease.ctx.Err() == nil {
		lease.retained = true
	}
}

// TransportClosed records a terminal reader handoff without canceling buffered
// output. The consumer still owns the turn until End; an already drained turn
// can release its retained lifecycle immediately.
func (lease *poolLease) TransportClosed(reason string) {
	lease.stateMu.Lock()
	lease.transportEnded = true
	lease.transportEndReason = reason
	finalized := lease.executionFinalized
	poolObserveLease(lease, "transport_closed", reason)
	lease.stateMu.Unlock()
	if finalized {
		lease.End(reason)
	}
}

func (lease *poolLease) finalizeExecution() {
	guard := lease.manager.poolGuard
	guard.mu.Lock()
	defer guard.mu.Unlock()
	if guard.receipts != nil && !lease.receiptFinal {
		if lease.receiptSSE {
			if err := lease.writeSSEFinalLocked(nil, "execution_ended_without_terminal"); err != nil {
				lease.receiptFailed = true
				lease.receiptState = "UNKNOWN"
			}
		} else {
			if err := guard.receipts.final(lease, lease.receiptState); err != nil {
				lease.receiptState = "UNKNOWN"
				lease.receiptFailed = true
				logEntryWithRequestID(lease.ctx).Warn("transport receipt persistence failed; evidence UNKNOWN")
			}
		}
	}
	guard.countsMu.Lock()
	guard.counts[lease.AuthID]--
	guard.countsMu.Unlock()
}

// End releases the turn's concurrency slot exactly once. A retained socket
// stays in the revocation table until session close or ownership transfer.
func (lease *poolLease) End(reason string) {
	lease.stateMu.Lock()
	defer lease.stateMu.Unlock()
	if lease.finalEnded {
		return
	}
	poolObserveLease(lease, "lease_end_begin", reason)
	if !lease.executionFinalized {
		lease.executionFinalized = true
		lease.finalizeExecution()
	}
	if lease.retained && !lease.transportEnded && reason == "stream_end" && lease.ctx.Err() == nil {
		lease.executionEnded = true
		poolObserveLease(lease, "turn_drained_retained", reason)
		return
	}
	lease.finalEnded = true
	if lease.retained && reason == "target_replaced" {
		// Codex installed the new lifecycle before ending the previous owner.
		// Disarm the old closer before canceling its context.
		lease.resourceMu.Lock()
		lease.closeFn = nil
		lease.resourceClosed = true
		lease.resourceMu.Unlock()
	}
	guard := lease.manager.poolGuard
	guard.mu.Lock()
	delete(guard.leases, lease.RequestID)
	guard.mu.Unlock()
	lease.cancel(nil)
	if lease.stopClose != nil {
		lease.stopClose()
	}
	lease.closeResource()
	poolObserveLease(lease, "lease_end_complete", reason)
}

func (lease *poolLease) AuthorizeDispatch() error {
	return lease.authorizeOperation(false)
}

func (lease *poolLease) AuthorizeConnect() error {
	return lease.authorizeOperation(true)
}

func (lease *poolLease) UpstreamDispatchStarted() error {
	guard := lease.manager.poolGuard
	if guard.receipts == nil {
		return nil
	}
	guard.mu.Lock()
	defer guard.mu.Unlock()
	if guard.leases[lease.RequestID] != lease || !lease.Dispatched {
		return ErrPoolGuard
	}
	if lease.receiptState == "STARTED" {
		return nil
	}
	if lease.receiptFailed {
		return ErrPoolGuard
	}
	if err := guard.receipts.started(lease); err != nil {
		lease.receiptState = "UNKNOWN"
		lease.receiptFailed = true
		lease.cancel(ErrPoolGuard)
		return ErrPoolGuard
	}
	lease.receiptState = "STARTED"
	return nil
}

func (lease *poolLease) authorizeOperation(connect bool) (err error) {
	guard := lease.manager.poolGuard
	guard.mu.Lock()
	defer guard.mu.Unlock()
	defer func() { poolObserveFence(lease, connect, err == nil) }()
	if lease.protocolAdmitted == nil || !lease.protocolAdmitted() {
		return poolAccountingError{cause: ErrPoolGuard, dispatched: lease.Dispatched}
	}
	// The existing receipt contract certifies HTTP non-stream invocations only.
	// Never mislabel a credential-bearing websocket handshake as zero transport.
	if connect && guard.receipts != nil {
		return ErrPoolGuard
	}
	if cause := context.Cause(lease.ctx); cause != nil {
		return cause
	}
	if guard.leases[lease.RequestID] != lease || lease.payloadAuthorized || connect && lease.connectAuthorized {
		return ErrPoolGuard
	}
	lease.manager.mu.RLock()
	current := lease.manager.auths[lease.AuthID]
	matches := current != nil && !current.Disabled && !ManagementIsolation(current) && current.Status != StatusDisabled && PoolCredentialDigest(current) == lease.CredentialDigest
	lease.manager.mu.RUnlock()
	if !matches {
		return ErrPoolGuard
	}
	record, err := lease.manager.poolGrants()
	if err != nil || record.Revision != lease.AuthorizationVersion {
		return ErrPoolGuard
	}
	trust, ok := guard.trusted(lease.auth, record.Revision)
	if !ok || trust.Generation != lease.Generation {
		return ErrPoolGuard
	}
	if _, err := lease.manager.matchPoolGrant(record, lease.auth, lease.req.Model, lease.caps); err != nil {
		return err
	}
	// Last admission boundary before upstream work: the canonical model's
	// capability must still be valid at dispatch time, not only at selection.
	reason, err := lease.manager.poolModelAdmitted(record, lease.auth, lease.req.Model)
	if err != nil {
		poolLogModelDecision(lease.ctx, lease.auth, lease.requestedModel, lease.req.Model, false, reason, record.Revision, lease.Generation)
		return err
	}
	if lease.consumeAttempt && !lease.Dispatched {
		budget, _ := lease.ctx.Value(poolAttemptContextKey{}).(*atomicPoolAttempt)
		if budget == nil || !budget.CompareAndSwap(false, true) {
			return ErrPoolGuard
		}
	}
	lease.Dispatched = true
	if guard.receipts != nil {
		lease.receiptState = "UNKNOWN"
	}
	if connect {
		lease.connectAuthorized = true
	} else {
		lease.payloadAuthorized = true
	}
	return nil
}
