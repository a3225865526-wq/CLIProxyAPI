//go:build clearapi_staging_observability

package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/google/uuid"
	logging "github.com/router-for-me/CLIProxyAPI/v8/internal/logging"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
	log "github.com/sirupsen/logrus"
)

type poolObservationKey struct{}
type poolObservationIdentity struct{ Request, Attempt, Session, Round string }

// This tagged observer has no writes to admission, publication or attempt state.
func poolObservationContext(ctx context.Context, opts cliproxyexecutor.Options) context.Context {
	if os.Getenv("CLEARAPI_PG02_OBSERVE") != "true" {
		return ctx
	}
	id := poolObservationIdentity{Request: logging.GetRequestID(ctx), Attempt: uuid.NewString(), Round: uuid.NewString(), Session: poolExecutionSessionID(opts)}
	return context.WithValue(ctx, poolObservationKey{}, id)
}

func poolObservationFields(ctx context.Context, event string) map[string]any {
	id, ok := ctx.Value(poolObservationKey{}).(poolObservationIdentity)
	if !ok || os.Getenv("CLEARAPI_PG02_OBSERVE") != "true" {
		return nil
	}
	return map[string]any{"event": event, "time_unix_ns": time.Now().UnixNano(), "request_id": id.Request, "attempt_id": id.Attempt, "attempt_id_kind": "server_observation_correlation", "session_id": id.Session, "round_id": id.Round}
}

func emitPoolObservation(fields map[string]any) {
	if fields == nil {
		return
	}
	data, err := json.Marshal(fields)
	if err == nil {
		log.Info("PG02_OBSERVATION " + string(data))
	}
}

// Caller holds manager.mu; the projection only copies current version fields.
func (m *Manager) poolObservationVersionsLocked(fields map[string]any, authID string) {
	if fields == nil {
		return
	}
	if a := m.auths[authID]; a != nil {
		fields["auth_id"] = a.ID
		fields["auth_generation"] = a.Generation
		fields["auth_disabled"] = a.Disabled
	}
	v, ok := m.poolRegistryVersions[authID]
	fields["registry_present"] = ok
	fields["registry_generation"] = v.generation
	fields["registry_revision"] = v.revision
}

func (m *Manager) poolObserveResultLocked(ctx context.Context, result Result, phase string) {
	if m.poolGuard == nil {
		return
	}
	fields := poolObservationFields(ctx, phase)
	if fields == nil {
		return
	}
	m.poolObservationVersionsLocked(fields, result.AuthID)
	fields["result_success"] = result.Success
	emitPoolObservation(fields)
}

// Caller holds poolGuard.mu, exactly at the actual authorization return path.
func poolObserveFence(lease *poolLease, connect, allowed bool) {
	fields := poolObservationFields(lease.ctx, "payload_fence")
	if fields == nil {
		return
	}
	m := lease.manager
	m.mu.RLock()
	m.poolObservationVersionsLocked(fields, lease.AuthID)
	m.mu.RUnlock()
	fields["connect_fence"] = connect
	fields["allowed"] = allowed
	fields["lease_id"] = lease.RequestID
	fields["trust_generation"] = lease.Generation
	fields["authorization_revision"] = lease.AuthorizationVersion
	fields["trust_capability_checked"] = allowed
	fields["dispatched"] = lease.Dispatched
	emitPoolObservation(fields)
}

// Caller holds stateMu. Do not read resource flags without their own mutex.
func poolObserveLease(lease *poolLease, event, reason string) {
	fields := poolObservationFields(lease.ctx, event)
	if fields == nil {
		return
	}
	fields["lease_id"] = lease.RequestID
	fields["reason"] = reason
	fields["retained"] = lease.retained
	fields["transport_ended"] = lease.transportEnded
	fields["turn_finalized"] = lease.executionFinalized
	fields["final_ended"] = lease.finalEnded
	fields["context_canceled"] = lease.ctx.Err() != nil
	fields["cancel_cause_type"] = fmt.Sprintf("%T", context.Cause(lease.ctx))
	emitPoolObservation(fields)
}

func (m *Manager) poolObservationSnapshot() any {
	if os.Getenv("CLEARAPI_PG02_OBSERVE") != "true" || m.poolGuard == nil {
		return nil
	}
	g := m.poolGuard
	g.mu.RLock()
	leases := make([]*poolLease, 0, len(g.leases))
	for _, l := range g.leases {
		leases = append(leases, l)
	}
	g.mu.RUnlock()
	rows := make([]map[string]any, 0, len(leases))
	for _, l := range leases {
		l.stateMu.Lock()
		row := map[string]any{"lease_id": l.RequestID, "session_id": l.sessionID, "retained": l.retained, "turn_finalized": l.executionFinalized, "final_ended": l.finalEnded, "transport_ended": l.transportEnded, "context_canceled": l.ctx.Err() != nil}
		l.stateMu.Unlock()
		l.resourceMu.Lock()
		row["resource_closed"] = l.resourceClosed
		l.resourceMu.Unlock()
		rows = append(rows, row)
	}
	g.countsMu.Lock()
	counts := make(map[string]int, len(g.counts))
	for id, c := range g.counts {
		counts[id] = c
	}
	g.countsMu.Unlock()
	buf := make([]byte, 256*1024)
	n := runtime.Stack(buf, true)
	functions := map[string]int{}
	for _, frame := range strings.Split(string(buf[:n]), "\n\n") {
		for _, name := range []string{"readUpstreamLoop", "streamCodexDuplex", "(*poolExecutor).ExecuteStream.func", "(*Manager).wrapStreamResult.func"} {
			if strings.Contains(frame, name) {
				functions[name]++
			}
		}
	}
	return map[string]any{"leases": rows, "concurrency": counts, "goroutines": runtime.NumGoroutine(), "execution_goroutines": functions, "stack_complete": n < len(buf)}
}
