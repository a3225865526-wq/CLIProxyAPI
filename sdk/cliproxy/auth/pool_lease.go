package auth

import (
	"context"
	"net/http"
	"sync"

	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
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
	manager           *Manager
	auth              *Auth
	req               cliproxyexecutor.Request
	caps              []string
	ctx               context.Context
	cancel            context.CancelCauseFunc
	once              sync.Once
	resourceMu        sync.Mutex
	closeFn           func() error
	resourceClosed    bool
	stopClose         func() bool
	consumeAttempt    bool
	connectAuthorized bool
	payloadAuthorized bool
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

func (lease *poolLease) End(string) {
	lease.once.Do(func() {
		guard := lease.manager.poolGuard
		guard.mu.Lock()
		delete(guard.leases, lease.RequestID)
		guard.countsMu.Lock()
		guard.counts[lease.AuthID]--
		guard.countsMu.Unlock()
		guard.mu.Unlock()
		lease.cancel(nil)
		if lease.stopClose != nil {
			lease.stopClose()
		}
		lease.closeResource()
	})
}

func (lease *poolLease) AuthorizeDispatch() error {
	return lease.authorizeOperation(false)
}

func (lease *poolLease) AuthorizeConnect() error {
	return lease.authorizeOperation(true)
}

func (lease *poolLease) authorizeOperation(connect bool) error {
	guard := lease.manager.poolGuard
	guard.mu.Lock()
	defer guard.mu.Unlock()
	if cause := context.Cause(lease.ctx); cause != nil {
		return cause
	}
	if guard.leases[lease.RequestID] != lease || lease.payloadAuthorized || connect && lease.connectAuthorized {
		return ErrPoolGuard
	}
	lease.manager.mu.RLock()
	current := lease.manager.auths[lease.AuthID]
	matches := current != nil && !current.Disabled && current.Status != StatusDisabled && PoolCredentialDigest(current) == lease.CredentialDigest
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
	if lease.consumeAttempt && !lease.Dispatched {
		budget, _ := lease.ctx.Value(poolAttemptContextKey{}).(*atomicPoolAttempt)
		if budget == nil || !budget.CompareAndSwap(false, true) {
			return ErrPoolGuard
		}
	}
	lease.Dispatched = true
	if connect {
		lease.connectAuthorized = true
	} else {
		lease.payloadAuthorized = true
	}
	return nil
}
