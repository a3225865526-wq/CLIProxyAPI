package auth

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
)

// PG-06 regression harness: a pool request that was actually dispatched to an
// upstream account must never be transparently replayed on another credential
// based on a response status. Typed pre-dispatch failures remain distinct.
// Non-pool traffic keeps its established failover contract.

func poolAttemptTestContext(ctx context.Context) context.Context {
	return context.WithValue(ctx, poolAttemptContextKey{}, &atomicPoolAttempt{})
}

func TestIntegrationDispatched400WithoutProofStopsReplay(t *testing.T) {
	ctx := newUpstreamAttemptContext(poolAttemptTestContext(context.Background()))
	cliproxyexecutor.MarkUpstreamAttempt(ctx)
	cause := &Error{HTTPStatus: http.StatusBadRequest, Message: "synthetic response with unknown provider work"}
	if !mustStopReplayAfterDispatch(ctx, "codex", cause) {
		t.Fatalf("dispatched HTTP 400 without no-work proof was classified replay-safe: definitive=%v attempted=%v work_observed=%v", definitiveUpstreamRejection(cause), cliproxyexecutor.UpstreamAttempted(ctx), cliproxyexecutor.UpstreamWorkObserved(ctx))
	}
}

func registerReplayGateAccounts(t *testing.T, m *Manager, provider, firstID, secondID string) {
	t.Helper()
	for _, candidate := range []*Auth{
		{ID: firstID, Provider: provider, Status: StatusActive, Attributes: map[string]string{"priority": "5"}},
		{ID: secondID, Provider: provider, Status: StatusActive, Attributes: map[string]string{"priority": "4"}},
	} {
		registry.GetGlobalRegistry().RegisterClient(candidate.ID, provider, []*registry.ModelInfo{{ID: "replay-model"}})
		t.Cleanup(func() { registry.GetGlobalRegistry().UnregisterClient(candidate.ID) })
		if _, errRegister := m.Register(context.Background(), candidate); errRegister != nil {
			t.Fatal(errRegister)
		}
	}
}

func TestManagerExecutePoolNoReplayAfterDispatchedTransportFailure(t *testing.T) {
	manager := NewManager(nil, &RoundRobinSelector{}, nil)
	manager.SetRetryConfig(3, 30*time.Second, 0)
	firstID, secondID := "replay-first-transport", "replay-second-transport"
	registerReplayGateAccounts(t, manager, "codex", firstID, secondID)

	var attempts []string
	manager.RegisterExecutor(&mockCustomErrorExecutor{
		identifier: "codex",
		executeFn: func(ctx context.Context, selected *Auth, _ cliproxyexecutor.Request, _ cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
			attempts = append(attempts, selected.ID)
			if selected.ID == firstID {
				cliproxyexecutor.MarkUpstreamAttempt(ctx)
				return cliproxyexecutor.Response{}, errors.New("connection reset by peer")
			}
			return cliproxyexecutor.Response{Payload: []byte(secondID)}, nil
		},
	})

	_, errExecute := manager.Execute(poolAttemptTestContext(context.Background()), []string{"codex"}, cliproxyexecutor.Request{Model: "replay-model"}, cliproxyexecutor.Options{})
	if errExecute == nil {
		t.Fatal("dispatched pool attempt that died on transport failure must not be replayed, want error")
	}
	if len(attempts) != 1 || attempts[0] != firstID {
		t.Fatalf("attempts = %v, want exactly the single dispatched attempt", attempts)
	}
}

func TestManagerExecutePoolNoReplayAfterDispatchedStatusRejection(t *testing.T) {
	manager := NewManager(nil, &RoundRobinSelector{}, nil)
	manager.SetRetryConfig(3, 30*time.Second, 0)
	firstID, secondID := "replay-first-reject", "replay-second-reject"
	registerReplayGateAccounts(t, manager, "codex", firstID, secondID)

	var attempts []string
	manager.RegisterExecutor(&mockCustomErrorExecutor{
		identifier: "codex",
		executeFn: func(ctx context.Context, selected *Auth, _ cliproxyexecutor.Request, _ cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
			attempts = append(attempts, selected.ID)
			if selected.ID == firstID {
				cliproxyexecutor.MarkUpstreamAttempt(ctx)
				return cliproxyexecutor.Response{}, &Error{HTTPStatus: http.StatusForbidden, Message: "forbidden"}
			}
			return cliproxyexecutor.Response{Payload: []byte(secondID)}, nil
		},
	})

	_, errExecute := manager.Execute(poolAttemptTestContext(context.Background()), []string{"codex"}, cliproxyexecutor.Request{Model: "replay-model"}, cliproxyexecutor.Options{})
	if errExecute == nil {
		t.Fatal("dispatched status rejection must not be transparently replayed")
	}
	if len(attempts) != 1 || attempts[0] != firstID {
		t.Fatalf("attempts = %v, want exactly the dispatched account", attempts)
	}
}

func TestManagerExecutePoolFailoverBeforeDispatch(t *testing.T) {
	manager := NewManager(nil, &RoundRobinSelector{}, nil)
	manager.SetRetryConfig(3, 30*time.Second, 0)
	firstID, secondID := "replay-first-predial", "replay-second-predial"
	registerReplayGateAccounts(t, manager, "codex", firstID, secondID)

	var attempts []string
	manager.RegisterExecutor(&mockCustomErrorExecutor{
		identifier: "codex",
		executeFn: func(ctx context.Context, selected *Auth, _ cliproxyexecutor.Request, _ cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
			attempts = append(attempts, selected.ID)
			if selected.ID == firstID {
				// No MarkUpstreamAttempt: the failure happened before any
				// transport boundary, so the upstream consumed nothing.
				return cliproxyexecutor.Response{}, errors.New("auth preparation failed")
			}
			return cliproxyexecutor.Response{Payload: []byte(secondID)}, nil
		},
	})

	response, errExecute := manager.Execute(poolAttemptTestContext(context.Background()), []string{"codex"}, cliproxyexecutor.Request{Model: "replay-model"}, cliproxyexecutor.Options{})
	if errExecute != nil {
		t.Fatalf("pre-dispatch failure may fail over, got error: %v", errExecute)
	}
	if len(attempts) != 2 {
		t.Fatalf("attempts = %v, want failed attempt then healthy account", attempts)
	}
	if string(response.Payload) != secondID {
		t.Fatalf("response = %s, want healthy account payload", response.Payload)
	}
}

func TestReplayGatePoolDispatchClassification(t *testing.T) {
	tests := []struct {
		name       string
		prepare    func(context.Context) error
		wantStop   bool
		wantStatus int
	}{
		{
			name: "ordinary 400 without proof",
			prepare: func(ctx context.Context) error {
				cliproxyexecutor.MarkUpstreamAttempt(ctx)
				return &Error{HTTPStatus: http.StatusBadRequest, Message: "provider rejected request"}
			},
			wantStop: true,
		},
		{
			name: "model_not_found body is not proof",
			prepare: func(ctx context.Context) error {
				cliproxyexecutor.MarkUpstreamAttempt(ctx)
				return &Error{HTTPStatus: http.StatusBadRequest, Message: `{"error":{"code":"model_not_found"}}`}
			},
			wantStop: true,
		},
		{
			name: "damaged body is not proof",
			prepare: func(ctx context.Context) error {
				cliproxyexecutor.MarkUpstreamAttempt(ctx)
				return &Error{HTTPStatus: http.StatusBadRequest, Message: "not json"}
			},
			wantStop: true,
		},
		{
			name: "wrapped 400 is not proof",
			prepare: func(ctx context.Context) error {
				cliproxyexecutor.MarkUpstreamAttempt(ctx)
				return WithCause(&Error{HTTPStatus: http.StatusBadRequest, Message: "wrapped"}, errors.New("transport wrapper"))
			},
			wantStop: true,
		},
		{
			name: "started without status is unknown",
			prepare: func(ctx context.Context) error {
				cliproxyexecutor.MarkUpstreamAttempt(ctx)
				return errors.New("provider result unknown")
			},
			wantStop: true,
		},
		{
			name: "unknown wrapped attempt stops",
			prepare: func(ctx context.Context) error {
				return markUpstreamExecutionAttempt(errors.New("wrapped provider result unknown"))
			},
			wantStop: true,
		},
		{
			name: "not started local rejection may replay",
			prepare: func(context.Context) error {
				return NewLocalModelResolutionError(`{"error":{"code":"model_not_found"}}`)
			},
			wantStop: false,
		},
		{
			name: "local typed error cannot mask started work",
			prepare: func(ctx context.Context) error {
				cliproxyexecutor.MarkUpstreamAttempt(ctx)
				return NewLocalModelResolutionError(`{"error":{"code":"model_not_found"}}`)
			},
			wantStop: true,
		},
		{
			name: "remapped 403 wrapper cannot authorize replay",
			prepare: func(ctx context.Context) error {
				cliproxyexecutor.MarkUpstreamAttempt(ctx)
				return WithCause(&Error{HTTPStatus: 403, Message: "remapped"}, &Error{HTTPStatus: 400, Message: "original"})
			},
			wantStop: true,
		},
		{
			name: "output or usage observed stops replay",
			prepare: func(ctx context.Context) error {
				cliproxyexecutor.MarkUpstreamWork(ctx)
				return &Error{HTTPStatus: 429, Message: "after output"}
			},
			wantStop: true,
		},
		{
			name: "401 after dispatch is not proof",
			prepare: func(ctx context.Context) error {
				cliproxyexecutor.MarkUpstreamAttempt(ctx)
				return &Error{HTTPStatus: http.StatusUnauthorized, Message: "expired"}
			},
			wantStop:   true,
			wantStatus: http.StatusUnauthorized,
		},
		{
			name: "403 after dispatch is not proof",
			prepare: func(ctx context.Context) error {
				cliproxyexecutor.MarkUpstreamAttempt(ctx)
				return &Error{HTTPStatus: http.StatusForbidden, Message: "forbidden"}
			},
			wantStop:   true,
			wantStatus: http.StatusForbidden,
		},
		{
			name: "404 after dispatch is not proof",
			prepare: func(ctx context.Context) error {
				cliproxyexecutor.MarkUpstreamAttempt(ctx)
				return &Error{HTTPStatus: http.StatusNotFound, Message: "missing"}
			},
			wantStop:   true,
			wantStatus: http.StatusNotFound,
		},
		{
			name: "429 after dispatch is not proof",
			prepare: func(ctx context.Context) error {
				cliproxyexecutor.MarkUpstreamAttempt(ctx)
				return &Error{HTTPStatus: http.StatusTooManyRequests, Message: "rate limited"}
			},
			wantStop:   true,
			wantStatus: http.StatusTooManyRequests,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx := newUpstreamAttemptContext(poolAttemptTestContext(context.Background()))
			err := test.prepare(ctx)
			if got := mustStopReplayAfterDispatch(ctx, "codex", err); got != test.wantStop {
				t.Fatalf("mustStopReplayAfterDispatch() = %v, want %v", got, test.wantStop)
			}
			if test.wantStatus != 0 && statusCodeFromError(err) != test.wantStatus {
				t.Fatalf("statusCodeFromError() = %d, want %d", statusCodeFromError(err), test.wantStatus)
			}
		})
	}
}

func TestManagerExecutePoolNoReplayAfterDispatched400WithoutProof(t *testing.T) {
	manager := NewManager(nil, &RoundRobinSelector{}, nil)
	manager.SetRetryConfig(3, 30*time.Second, 0)
	firstID, secondID := "replay-first-400", "replay-second-400"
	registerReplayGateAccounts(t, manager, "codex", firstID, secondID)

	attempts := make([]string, 0, 2)
	manager.RegisterExecutor(&mockCustomErrorExecutor{
		identifier: "codex",
		executeFn: func(ctx context.Context, selected *Auth, _ cliproxyexecutor.Request, _ cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
			attempts = append(attempts, selected.ID)
			cliproxyexecutor.MarkUpstreamAttempt(ctx)
			return cliproxyexecutor.Response{}, &Error{HTTPStatus: http.StatusBadRequest, Message: "ordinary provider 400"}
		},
	})

	_, errExecute := manager.Execute(poolAttemptTestContext(context.Background()), []string{"codex"}, cliproxyexecutor.Request{Model: "replay-model"}, cliproxyexecutor.Options{})
	if errExecute == nil {
		t.Fatal("dispatched ordinary 400 must not be transparently replayed")
	}
	if len(attempts) != 1 || attempts[0] != firstID {
		t.Fatalf("attempts = %v, want exactly the first dispatched account", attempts)
	}
}

func TestManagerExecutePoolNoReplayAfterDispatchedServerError(t *testing.T) {
	manager := NewManager(nil, &RoundRobinSelector{}, nil)
	manager.SetRetryConfig(3, 30*time.Second, 0)
	firstID, secondID := "replay-first-5xx", "replay-second-5xx"
	registerReplayGateAccounts(t, manager, "codex", firstID, secondID)

	var attempts []string
	manager.RegisterExecutor(&mockCustomErrorExecutor{
		identifier: "codex",
		executeFn: func(ctx context.Context, selected *Auth, _ cliproxyexecutor.Request, _ cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
			attempts = append(attempts, selected.ID)
			if selected.ID == firstID {
				cliproxyexecutor.MarkUpstreamAttempt(ctx)
				return cliproxyexecutor.Response{}, &Error{HTTPStatus: http.StatusBadGateway, Message: "bad gateway"}
			}
			return cliproxyexecutor.Response{Payload: []byte(secondID)}, nil
		},
	})

	_, errExecute := manager.Execute(poolAttemptTestContext(context.Background()), []string{"codex"}, cliproxyexecutor.Request{Model: "replay-model"}, cliproxyexecutor.Options{})
	if errExecute == nil {
		t.Fatal("dispatched pool attempt that ended in 5xx must not be replayed, want error")
	}
	if len(attempts) != 1 {
		t.Fatalf("attempts = %v, want exactly the single dispatched attempt", attempts)
	}
}

func TestManagerExecuteCodexNoReplayAfterObservedWork(t *testing.T) {
	manager := NewManager(nil, &RoundRobinSelector{}, nil)
	manager.SetRetryConfig(3, 30*time.Second, 0)
	firstID, secondID := "replay-first-work", "replay-second-work"
	registerReplayGateAccounts(t, manager, "codex", firstID, secondID)

	var attempts []string
	manager.RegisterExecutor(&mockCustomErrorExecutor{
		identifier: "codex",
		executeFn: func(ctx context.Context, selected *Auth, _ cliproxyexecutor.Request, _ cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
			attempts = append(attempts, selected.ID)
			if selected.ID == firstID {
				cliproxyexecutor.MarkUpstreamAttempt(ctx)
				cliproxyexecutor.MarkUpstreamWork(ctx)
				return cliproxyexecutor.Response{}, errors.New("stream broken after first delta")
			}
			return cliproxyexecutor.Response{Payload: []byte(secondID)}, nil
		},
	})

	_, errExecute := manager.Execute(context.Background(), []string{"codex"}, cliproxyexecutor.Request{Model: "replay-model"}, cliproxyexecutor.Options{})
	if errExecute == nil {
		t.Fatal("codex attempt with observed upstream output must not be replayed, want error")
	}
	if len(attempts) != 1 {
		t.Fatalf("attempts = %v, want exactly the single observed attempt", attempts)
	}
}

func TestManagerExecuteNonPoolKeepsFailoverAfterDispatchedServerError(t *testing.T) {
	manager := NewManager(nil, &RoundRobinSelector{}, nil)
	manager.SetRetryConfig(3, 30*time.Second, 0)
	firstID, secondID := "replay-nonpool-first", "replay-nonpool-second"
	registerReplayGateAccounts(t, manager, "claude", firstID, secondID)

	var attempts []string
	manager.RegisterExecutor(&mockCustomErrorExecutor{
		identifier: "claude",
		executeFn: func(ctx context.Context, selected *Auth, _ cliproxyexecutor.Request, _ cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
			attempts = append(attempts, selected.ID)
			if selected.ID == firstID {
				cliproxyexecutor.MarkUpstreamAttempt(ctx)
				return cliproxyexecutor.Response{}, &Error{HTTPStatus: http.StatusBadGateway, Message: "bad gateway"}
			}
			return cliproxyexecutor.Response{Payload: []byte(secondID)}, nil
		},
	})

	_, errExecute := manager.Execute(context.Background(), []string{"claude"}, cliproxyexecutor.Request{Model: "replay-model"}, cliproxyexecutor.Options{})
	if errExecute != nil {
		t.Fatalf("non-pool traffic keeps its failover contract, got error: %v", errExecute)
	}
	if len(attempts) != 2 {
		t.Fatalf("attempts = %v, want failed attempt then healthy account", attempts)
	}
}

func TestManagerExecuteStreamPoolNoReplayAfterDispatchedEmptyStream(t *testing.T) {
	manager := NewManager(nil, &RoundRobinSelector{}, nil)
	manager.SetRetryConfig(3, 30*time.Second, 0)
	firstID, secondID := "replay-first-stream", "replay-second-stream"
	registerReplayGateAccounts(t, manager, "codex", firstID, secondID)

	var attempts []string
	manager.RegisterExecutor(&customStreamMockExecutor{
		identifier: "codex",
		mockCustomErrorExecutor: mockCustomErrorExecutor{
			executeFn: func(ctx context.Context, selected *Auth, _ cliproxyexecutor.Request, _ cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
				attempts = append(attempts, selected.ID)
				return cliproxyexecutor.Response{Payload: []byte(selected.ID)}, nil
			},
		},
		streamFn: func(ctx context.Context, selected *Auth, _ cliproxyexecutor.Request, _ cliproxyexecutor.Options) (*cliproxyexecutor.StreamResult, error) {
			attempts = append(attempts, selected.ID)
			if selected.ID == firstID {
				cliproxyexecutor.MarkUpstreamAttempt(ctx)
				chunks := make(chan cliproxyexecutor.StreamChunk)
				close(chunks)
				return &cliproxyexecutor.StreamResult{Chunks: chunks}, nil
			}
			chunks := make(chan cliproxyexecutor.StreamChunk, 1)
			chunks <- cliproxyexecutor.StreamChunk{Payload: []byte(secondID)}
			close(chunks)
			return &cliproxyexecutor.StreamResult{Chunks: chunks}, nil
		},
	})

	_, errStream := manager.ExecuteStream(poolAttemptTestContext(context.Background()), []string{"codex"}, cliproxyexecutor.Request{Model: "replay-model"}, cliproxyexecutor.Options{Stream: true})
	if errStream == nil {
		t.Fatal("dispatched pool attempt whose stream died before the first payload must not be replayed, want error")
	}
	firstAccountAttempts := 0
	for _, id := range attempts {
		if id == firstID {
			firstAccountAttempts++
		}
	}
	if firstAccountAttempts != 1 {
		t.Fatalf("first-account stream attempts = %d, want exactly one dispatched attempt (all attempts: %v)", firstAccountAttempts, attempts)
	}
}
