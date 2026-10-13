package auth

import (
	"errors"
	"fmt"
)

// RuntimeRetryDiagnostic exposes a fixed, secret-free projection of the actual
// manager atomics, target Auth.Metadata override and registered pool executor.
// It never selects an account, acquires a lease, or invokes an executor.
func (m *Manager) RuntimeRetryDiagnostic() (any, error) {
	if m == nil {
		return nil, errors.New("runtime manager unavailable")
	}
	global, credentials, interval := m.retrySettings()
	m.mu.RLock()
	target := m.auths["codex-real-test.json"]
	if target == nil || target.Provider != "codex" || target.AuthKind() != AuthKindOAuth {
		m.mu.RUnlock()
		return nil, errors.New("runtime target unavailable")
	}
	override, overridePresent := target.RequestRetryOverride()
	effective := effectiveRequestRetryLimit(target, global)
	wrapped, wrappedOK := m.executors["codex"].(*poolExecutor)
	executorType := "unavailable"
	fenced := false
	if wrappedOK && wrapped != nil {
		executorType = fmt.Sprintf("%T", wrapped.ProviderExecutor)
		if guard, ok := wrapped.ProviderExecutor.(interface{ PoolDispatchFencing() bool }); ok {
			fenced = guard.PoolDispatchFencing()
		}
	}
	m.mu.RUnlock()
	role := m.PoolRole()
	home, plugins := m.HomeEnabled(), m.hasPluginScheduler()
	knownHTTP := executorType == "*executor.CodexAutoExecutor" || executorType == "*executor.CodexExecutor"
	protected := wrappedOK && fenced && role == "service" && !home && !plugins && knownHTTP
	var overrideValue *int
	if overridePresent {
		overrideValue = &override
	}
	var receiptIdentity map[string]any
	if m.poolGuard != nil && m.poolGuard.receipts != nil {
		writer := m.poolGuard.receipts
		receiptIdentity = map[string]any{"process_epoch": writer.processEpoch, "process_id": writer.processID, "process_start_ticks": writer.startTicks, "executor_binary_sha256": writer.binarySHA}
	}
	return struct {
		AuthID                    string         `json:"auth_id"`
		Model                     string         `json:"model"`
		GlobalRetry               int            `json:"global_request_retry"`
		MaxRetryCredentials       int            `json:"max_retry_credentials"`
		MaxRetryIntervalMS        int64          `json:"max_retry_interval_ms"`
		CredentialOverridePresent bool           `json:"credential_retry_override_present"`
		CredentialOverride        *int           `json:"credential_retry_override"`
		EffectiveRequestRetry     int            `json:"effective_request_retry"`
		PoolRole                  string         `json:"pool_role"`
		HomeEnabled               bool           `json:"home_enabled"`
		PluginScheduler           bool           `json:"plugin_scheduler_enabled"`
		ExecutorType              string         `json:"registered_executor"`
		PoolWrapped               bool           `json:"pool_wrapped"`
		DispatchFence             bool           `json:"dispatch_fence"`
		HTTPNonStream             bool           `json:"http_nonstream_uses_http_executor"`
		RouterRetryPolicy         string         `json:"router_retry_policy"`
		FailoverBoundary          string         `json:"retry_failover_boundary"`
		AtMostOneDispatch         bool           `json:"at_most_one_provider_dispatch"`
		ReceiptIdentity           map[string]any `json:"transport_receipt_identity,omitempty"`
		PoolObservation           any            `json:"pool_observation,omitempty"`
	}{"codex-real-test.json", "gpt-5.6-luna", global, credentials, interval.Milliseconds(), overridePresent, overrideValue, effective, role, home, plugins, executorType, wrappedOK, fenced, knownHTTP,
		"single Manager.Execute invocation; websocket bootstrap retries do not apply to HTTP non-stream",
		"pool atomic attempt budget consumed at transport boundary; pre-dispatch failover allowed; second provider dispatch refused", protected, receiptIdentity, m.poolObservationSnapshot()}, nil
}
