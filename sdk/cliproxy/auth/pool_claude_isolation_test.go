package auth

import (
	"context"
	"errors"
	"net/http"
	"sync/atomic"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
)

// claudeProbeExecutor mirrors poolProbeExecutor for the claude provider so the
// isolation tests can prove no upstream dispatch ever happens.
type claudeProbeExecutor struct {
	calls atomic.Int32
}

func (*claudeProbeExecutor) Identifier() string { return "claude" }

func (e *claudeProbeExecutor) Execute(ctx context.Context, _ *Auth, _ cliproxyexecutor.Request, _ cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
	if err := cliproxyexecutor.BeforeUpstreamDispatch(ctx); err != nil {
		return cliproxyexecutor.Response{}, err
	}
	e.calls.Add(1)
	return cliproxyexecutor.Response{Payload: []byte(`{"usage":{"input_tokens":1,"output_tokens":1,"total_tokens":2}}`)}, nil
}

func (e *claudeProbeExecutor) ExecuteStream(ctx context.Context, _ *Auth, _ cliproxyexecutor.Request, _ cliproxyexecutor.Options) (*cliproxyexecutor.StreamResult, error) {
	if err := cliproxyexecutor.BeforeUpstreamDispatch(ctx); err != nil {
		return nil, err
	}
	e.calls.Add(1)
	return &cliproxyexecutor.StreamResult{Chunks: make(chan cliproxyexecutor.StreamChunk)}, nil
}

func (*claudeProbeExecutor) Refresh(_ context.Context, a *Auth) (*Auth, error) { return a.Clone(), nil }

func (e *claudeProbeExecutor) CountTokens(ctx context.Context, a *Auth, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
	return e.Execute(ctx, a, req, opts)
}

func (*claudeProbeExecutor) HttpRequest(context.Context, *Auth, *http.Request) (*http.Response, error) {
	return nil, nil
}

// STEP 5: in pool mode a claude-provider account is never admitted — not by
// selection, not by the wrapped executor, not by a capability grant — and the
// Codex OAuth pool stays unreachable from Claude traffic.
func TestPoolGuardNeverAdmitsClaudeProvider(t *testing.T) {
	m, _, _, _, record := poolGuardFixture(t, "service")
	claudeExecutor := &claudeProbeExecutor{}
	m.RegisterExecutor(claudeExecutor)

	claudeAuth := &Auth{
		ID:         "synthetic-claude-account",
		Provider:   "claude",
		FileName:   "claude-synthetic.json",
		Status:     StatusActive,
		Attributes: map[string]string{AttributeAuthKind: AuthKindOAuth},
		Metadata:   map[string]any{"access_token": "synthetic-unused"},
	}
	registered, err := m.Register(context.Background(), claudeAuth)
	if err != nil {
		t.Fatal(err)
	}

	// Selection never yields the claude account, regardless of the model name
	// it is asked for — including a name published for the codex pool.
	for _, model := range []string{"claude-sonnet-4-5", record.Grants[0].Models[0]} {
		if m.poolCandidateAllowed(registered, model, cliproxyexecutor.Options{}) {
			t.Fatalf("claude candidate admitted for model %q", model)
		}
		if _, err := m.Execute(context.Background(), []string{"claude"}, cliproxyexecutor.Request{Model: model}, cliproxyexecutor.Options{}); err == nil {
			t.Fatalf("claude execution admitted for model %q", model)
		}
		if executorCalls := claudeExecutor.calls.Load(); executorCalls != 0 {
			t.Fatalf("claude upstream dispatched %d times for model %q", executorCalls, model)
		}
		if _, err := m.ExecuteStream(context.Background(), []string{"claude"}, cliproxyexecutor.Request{Model: model}, cliproxyexecutor.Options{Stream: true}); err == nil {
			t.Fatalf("claude stream admitted for model %q", model)
		}
	}

	// The wrapped executor rejects a direct claude dispatch as a pool
	// accounting termination (fail closed, no upstream attempt).
	wrapped, ok := m.Executor("claude")
	if !ok {
		t.Fatal("claude executor missing from manager")
	}
	directAuth, found := m.GetByID(registered.ID)
	if !found || directAuth == nil {
		t.Fatal("claude auth missing from manager")
	}
	if _, err := wrapped.Execute(context.Background(), directAuth, cliproxyexecutor.Request{Model: "claude-sonnet-4-5"}, cliproxyexecutor.Options{}); err == nil {
		t.Fatal("direct claude dispatch admitted")
	} else {
		var termination poolAccountingError
		if !errors.As(err, &termination) {
			t.Fatalf("claude dispatch error is not a pool accounting termination: %v", err)
		}
	}
	if executorCalls := claudeExecutor.calls.Load(); executorCalls != 0 {
		t.Fatalf("claude upstream dispatched %d times via wrapped executor", executorCalls)
	}

	// The capability system does not extend to claude identities: granting a
	// model for the claude account must fail (no trusted record to bind to).
	command := PoolModelGrant{ExpectedRevision: record.Revision, Identity: PoolIdentityExpectation{AuthID: registered.ID, Provider: "claude", CredentialDigest: PoolCredentialDigest(registered), Generation: 1}, Model: "claude-sonnet-4-5"}
	if err := m.GrantPoolModelCapability(context.Background(), command); err == nil {
		t.Fatal("pool capability granted for a claude identity")
	}
	if executorCalls := claudeExecutor.calls.Load(); executorCalls != 0 {
		t.Fatalf("claude upstream dispatched %d times after grant attempt", executorCalls)
	}
}

// Without pool mode the guard is nil: claude accounts execute exactly as
// before, with no pool evaluation anywhere in the path.
func TestPoolOffKeepsClaudeExecutionUntouched(t *testing.T) {
	m, _, _, _, _ := poolGuardFixture(t, "")
	if m.poolGuard != nil {
		t.Fatal("pool guard constructed without CLEARAPI_POOL_ROLE")
	}
	claudeExecutor := &claudeProbeExecutor{}
	m.RegisterExecutor(claudeExecutor)
	claudeAuth := &Auth{
		ID:         "synthetic-claude-account-open",
		Provider:   "claude",
		FileName:   "claude-synthetic-open.json",
		Status:     StatusActive,
		Attributes: map[string]string{AttributeAuthKind: AuthKindAPIKey},
		Metadata:   map[string]any{},
	}
	if _, err := m.Register(context.Background(), claudeAuth); err != nil {
		t.Fatal(err)
	}
	registry.GetGlobalRegistry().RegisterClient(claudeAuth.ID, claudeAuth.Provider, []*registry.ModelInfo{{ID: "claude-sonnet-4-5"}})
	t.Cleanup(func() { registry.GetGlobalRegistry().UnregisterClient(claudeAuth.ID) })
	if _, err := m.Execute(context.Background(), []string{"claude"}, cliproxyexecutor.Request{Model: "claude-sonnet-4-5"}, cliproxyexecutor.Options{}); err != nil {
		t.Fatalf("claude execution rejected without pool mode: %v", err)
	}
	if executorCalls := claudeExecutor.calls.Load(); executorCalls != 1 {
		t.Fatalf("claude upstream calls = %d, want 1", executorCalls)
	}
}
