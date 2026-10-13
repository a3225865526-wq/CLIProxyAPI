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

// geminiXaiProbeExecutor mirrors poolProbeExecutor for the gemini and xai
// providers so the isolation tests can prove no upstream dispatch ever
// happens for non-codex accounts in pool mode.
type geminiXaiProbeExecutor struct {
	identifier string
	calls      atomic.Int32
}

func (e *geminiXaiProbeExecutor) Identifier() string { return e.identifier }

func (e *geminiXaiProbeExecutor) Execute(ctx context.Context, _ *Auth, _ cliproxyexecutor.Request, _ cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
	if err := cliproxyexecutor.BeforeUpstreamDispatch(ctx); err != nil {
		return cliproxyexecutor.Response{}, err
	}
	e.calls.Add(1)
	return cliproxyexecutor.Response{Payload: []byte(`{"usage":{"input_tokens":1,"output_tokens":1,"total_tokens":2}}`)}, nil
}

func (e *geminiXaiProbeExecutor) ExecuteStream(ctx context.Context, _ *Auth, _ cliproxyexecutor.Request, _ cliproxyexecutor.Options) (*cliproxyexecutor.StreamResult, error) {
	if err := cliproxyexecutor.BeforeUpstreamDispatch(ctx); err != nil {
		return nil, err
	}
	e.calls.Add(1)
	return &cliproxyexecutor.StreamResult{Chunks: make(chan cliproxyexecutor.StreamChunk)}, nil
}

func (e *geminiXaiProbeExecutor) Refresh(_ context.Context, a *Auth) (*Auth, error) { return a.Clone(), nil }

func (e *geminiXaiProbeExecutor) CountTokens(ctx context.Context, a *Auth, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
	return e.Execute(ctx, a, req, opts)
}

func (*geminiXaiProbeExecutor) HttpRequest(context.Context, *Auth, *http.Request) (*http.Response, error) {
	return nil, nil
}

// STEP 6: in pool mode a gemini or xai account is never admitted — not by
// selection, not by the wrapped executor, not by a capability grant, and not
// by disguising the request as a published Codex pool model name. The Codex
// OAuth pool stays unreachable from Gemini/Grok traffic.
func TestPoolGuardNeverAdmitsGeminiOrXaiProviders(t *testing.T) {
	m, _, _, _, record := poolGuardFixture(t, "service")
	publishedModel := record.Grants[0].Models[0]

	cases := []struct {
		provider string
		authKind string
	}{
		{provider: "gemini", authKind: AuthKindAPIKey},
		{provider: "xai", authKind: AuthKindOAuth},
		{provider: "xai", authKind: AuthKindAPIKey},
	}

	for _, tc := range cases {
		t.Run(tc.provider+"-"+tc.authKind, func(t *testing.T) {
			executor := &geminiXaiProbeExecutor{identifier: tc.provider}
			m.RegisterExecutor(executor)

			ownModel := "gemini-2.5-pro"
			if tc.provider == "xai" {
				ownModel = "grok-4"
			}
			auth := &Auth{
				ID:         "synthetic-" + tc.provider + "-account",
				Provider:   tc.provider,
				FileName:   tc.provider + "-synthetic.json",
				Status:     StatusActive,
				Attributes: map[string]string{AttributeAuthKind: tc.authKind},
				Metadata:   map[string]any{"access_token": "synthetic-unused"},
			}
			registered, err := m.Register(context.Background(), auth)
			if err != nil {
				t.Fatal(err)
			}
			registry.GetGlobalRegistry().RegisterClient(registered.ID, registered.Provider, []*registry.ModelInfo{{ID: ownModel}})
			t.Cleanup(func() { registry.GetGlobalRegistry().UnregisterClient(registered.ID) })

			// Selection never yields the account — for its own model name, for
			// a published Codex pool model name, and for a Codex-style alias.
			for _, model := range []string{ownModel, publishedModel, "gpt-5-codex"} {
				if m.poolCandidateAllowed(registered, model, cliproxyexecutor.Options{}) {
					t.Fatalf("%s candidate admitted for model %q", tc.provider, model)
				}
				if _, err := m.Execute(context.Background(), []string{tc.provider}, cliproxyexecutor.Request{Model: model}, cliproxyexecutor.Options{}); err == nil {
					t.Fatalf("%s execution admitted for model %q", tc.provider, model)
				}
				if _, err := m.ExecuteStream(context.Background(), []string{tc.provider}, cliproxyexecutor.Request{Model: model}, cliproxyexecutor.Options{Stream: true}); err == nil {
					t.Fatalf("%s stream admitted for model %q", tc.provider, model)
				}
			}
			if executorCalls := executor.calls.Load(); executorCalls != 0 {
				t.Fatalf("%s upstream dispatched %d times", tc.provider, executorCalls)
			}

			// The wrapped executor rejects a direct dispatch as a pool
			// accounting termination (fail closed, no upstream attempt).
			wrapped, ok := m.Executor(tc.provider)
			if !ok {
				t.Fatalf("%s executor missing from manager", tc.provider)
			}
			directAuth, found := m.GetByID(registered.ID)
			if !found || directAuth == nil {
				t.Fatalf("%s auth missing from manager", tc.provider)
			}
			if _, err := wrapped.Execute(context.Background(), directAuth, cliproxyexecutor.Request{Model: ownModel}, cliproxyexecutor.Options{}); err == nil {
				t.Fatalf("direct %s dispatch admitted", tc.provider)
			} else {
				var termination poolAccountingError
				if !errors.As(err, &termination) {
					t.Fatalf("%s dispatch error is not a pool accounting termination: %v", tc.provider, err)
				}
			}
			if executorCalls := executor.calls.Load(); executorCalls != 0 {
				t.Fatalf("%s upstream dispatched %d times via wrapped executor", tc.provider, executorCalls)
			}

			// The capability system does not extend to gemini/xai identities:
			// granting a model for the account must fail (no trusted record).
			command := PoolModelGrant{
				ExpectedRevision: record.Revision,
				Identity:         PoolIdentityExpectation{AuthID: registered.ID, Provider: tc.provider, CredentialDigest: PoolCredentialDigest(registered), Generation: 1},
				Model:            ownModel,
			}
			if err := m.GrantPoolModelCapability(context.Background(), command); err == nil {
				t.Fatalf("pool capability granted for a %s identity", tc.provider)
			}
			if executorCalls := executor.calls.Load(); executorCalls != 0 {
				t.Fatalf("%s upstream dispatched %d times after grant attempt", tc.provider, executorCalls)
			}
		})
	}
}

// Without pool mode the guard is nil: gemini and xai accounts execute exactly
// as before, with no pool evaluation anywhere in the path.
func TestPoolOffKeepsGeminiAndXaiExecutionUntouched(t *testing.T) {
	m, _, _, _, _ := poolGuardFixture(t, "")
	if m.poolGuard != nil {
		t.Fatal("pool guard constructed without CLEARAPI_POOL_ROLE")
	}
	geminiExecutor := &geminiXaiProbeExecutor{identifier: "gemini"}
	xaiExecutor := &geminiXaiProbeExecutor{identifier: "xai"}
	m.RegisterExecutor(geminiExecutor)
	m.RegisterExecutor(xaiExecutor)

	geminiAuth := &Auth{
		ID:         "synthetic-gemini-account-open",
		Provider:   "gemini",
		FileName:   "gemini-synthetic-open.json",
		Status:     StatusActive,
		Attributes: map[string]string{AttributeAuthKind: AuthKindAPIKey},
		Metadata:   map[string]any{},
	}
	if _, err := m.Register(context.Background(), geminiAuth); err != nil {
		t.Fatal(err)
	}
	registry.GetGlobalRegistry().RegisterClient(geminiAuth.ID, geminiAuth.Provider, []*registry.ModelInfo{{ID: "gemini-2.5-pro"}})
	t.Cleanup(func() { registry.GetGlobalRegistry().UnregisterClient(geminiAuth.ID) })
	if _, err := m.Execute(context.Background(), []string{"gemini"}, cliproxyexecutor.Request{Model: "gemini-2.5-pro"}, cliproxyexecutor.Options{}); err != nil {
		t.Fatalf("gemini execution rejected without pool mode: %v", err)
	}
	if calls := geminiExecutor.calls.Load(); calls != 1 {
		t.Fatalf("gemini upstream calls = %d, want 1", calls)
	}

	xaiAuth := &Auth{
		ID:         "synthetic-xai-account-open",
		Provider:   "xai",
		FileName:   "xai-synthetic-open.json",
		Status:     StatusActive,
		Attributes: map[string]string{AttributeAuthKind: AuthKindOAuth},
		Metadata:   map[string]any{"access_token": "synthetic-unused"},
	}
	if _, err := m.Register(context.Background(), xaiAuth); err != nil {
		t.Fatal(err)
	}
	registry.GetGlobalRegistry().RegisterClient(xaiAuth.ID, xaiAuth.Provider, []*registry.ModelInfo{{ID: "grok-4"}})
	t.Cleanup(func() { registry.GetGlobalRegistry().UnregisterClient(xaiAuth.ID) })
	if _, err := m.Execute(context.Background(), []string{"xai"}, cliproxyexecutor.Request{Model: "grok-4"}, cliproxyexecutor.Options{}); err != nil {
		t.Fatalf("xai execution rejected without pool mode: %v", err)
	}
	if calls := xaiExecutor.calls.Load(); calls != 1 {
		t.Fatalf("xai upstream calls = %d, want 1", calls)
	}
}
