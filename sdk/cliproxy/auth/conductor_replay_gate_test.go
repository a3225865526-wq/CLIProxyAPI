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
// unless the upstream returned a definitive pre-execution rejection (4xx).
// Non-pool traffic keeps its established failover contract.

func poolAttemptTestContext(ctx context.Context) context.Context {
	return context.WithValue(ctx, poolAttemptContextKey{}, &atomicPoolAttempt{})
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

func TestManagerExecutePoolFailoverAfterDefinitiveRejection(t *testing.T) {
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

	response, errExecute := manager.Execute(poolAttemptTestContext(context.Background()), []string{"codex"}, cliproxyexecutor.Request{Model: "replay-model"}, cliproxyexecutor.Options{})
	if errExecute != nil {
		t.Fatalf("definitive 4xx rejection may fail over, got error: %v", errExecute)
	}
	if len(attempts) != 2 || attempts[0] != firstID || attempts[1] != secondID {
		t.Fatalf("attempts = %v, want rejected account then healthy account", attempts)
	}
	if string(response.Payload) != secondID {
		t.Fatalf("response = %s, want healthy account payload", response.Payload)
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
