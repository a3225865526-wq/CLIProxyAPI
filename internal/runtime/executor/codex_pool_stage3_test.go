package executor

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	coreexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
	sdktranslator "github.com/router-for-me/CLIProxyAPI/v8/sdk/translator"
)

func revokeCodexPoolModel(t *testing.T, manager *coreauth.Manager, auth *coreauth.Auth, model string) {
	t.Helper()
	revision, states, err := manager.PoolTrustSnapshot()
	if err != nil {
		t.Fatal(err)
	}
	identity := coreauth.PoolIdentityExpectation{AuthID: auth.ID, Provider: auth.Provider, CredentialDigest: coreauth.PoolCredentialDigest(auth)}
	for _, state := range states {
		if state.AuthID == auth.ID {
			identity.Generation = state.Generation
		}
	}
	if err := manager.RevokePoolModelCapability(context.Background(), coreauth.PoolModelRevoke{ExpectedRevision: revision, Identity: identity, Model: model}); err != nil {
		t.Fatal(err)
	}
}

// The real Codex executor must refuse to dispatch a model whose capability was
// revoked after selection, for both the HTTP and the websocket transport.
func TestCodexPoolModelCapabilityRevoke(t *testing.T) {
	const final = `{"type":"response.completed","response":{"id":"synthetic-stage3","status":"completed","output":[],"usage":{"input_tokens":100,"output_tokens":20,"total_tokens":120}}}`
	for _, kind := range []string{"http", "websocket"} {
		t.Run(kind, func(t *testing.T) {
			var calls atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				if kind == "http" {
					w.Header().Set("Content-Type", "text/event-stream")
					_, _ = w.Write([]byte("data: " + final + "\n\n"))
					return
				}
				conn, err := (&websocket.Upgrader{}).Upgrade(w, r, nil)
				if err != nil {
					return
				}
				defer conn.Close()
				if _, _, err := conn.ReadMessage(); err == nil {
					_ = conn.WriteMessage(websocket.TextMessage, []byte(final))
				}
			}))
			defer server.Close()
			manager, auth := codexPoolFixture(t, server.URL, kind == "websocket")
			manager.SetRetryConfig(3, 0, 3)
			ctx := context.Background()
			if kind == "websocket" {
				ctx = coreexecutor.WithDownstreamWebsocket(ctx)
			}
			request := coreexecutor.Request{Model: "synthetic-native", Payload: []byte(`{"model":"synthetic-native","input":"synthetic"}`)}
			opts := coreexecutor.Options{SourceFormat: sdktranslator.FormatOpenAIResponse}
			result, err := manager.Execute(ctx, []string{"codex"}, request, opts)
			if err != nil || len(result.Payload) == 0 {
				t.Fatalf("admitted model failed before revoke: %v", err)
			}
			if calls.Load() != 1 {
				t.Fatalf("admitted model upstream calls = %d", calls.Load())
			}
			revokeCodexPoolModel(t, manager, auth, "synthetic-native")
			_, err = manager.Execute(ctx, []string{"codex"}, request, opts)
			// The router filter refuses with pool_no_eligible_account before any
			// pick; a racing selection would fail closed with ErrPoolGuard.
			var authErr *coreauth.Error
			if err == nil || calls.Load() != 1 || (!(errors.As(err, &authErr) && authErr.Code == "pool_no_eligible_account") && !errors.Is(err, coreauth.ErrPoolGuard)) {
				t.Fatalf("revoked model dispatched or wrong denial: err=%v calls=%d", err, calls.Load())
			}
			if len(manager.PoolInFlightSnapshot()) != 0 {
				t.Fatal("lease leak after revoked model request")
			}
		})
	}
}

// A model revoke that lands while the request is already dispatched must
// terminate the local request without a second upstream attempt.
func TestCodexPoolModelRevokeInFlightTerminatesWithoutReplay(t *testing.T) {
	var calls atomic.Int32
	entered := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte("data: {\"type\":\"response.created\",\"response\":{\"id\":\"synthetic\"}}\n\n"))
		w.(http.Flusher).Flush()
		close(entered)
		<-r.Context().Done()
	}))
	defer server.Close()
	manager, auth := codexPoolFixture(t, server.URL, false)
	manager.SetRetryConfig(3, 0, 3)
	result := make(chan error, 1)
	go func() {
		_, err := manager.Execute(context.Background(), []string{"codex"}, coreexecutor.Request{Model: "synthetic-native", Payload: []byte(`{"model":"synthetic-native","input":"synthetic"}`)}, coreexecutor.Options{SourceFormat: sdktranslator.FormatOpenAIResponse})
		result <- err
	}()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("no synthetic dispatch")
	}
	revokeCodexPoolModel(t, manager, auth, "synthetic-native")
	select {
	case err := <-result:
		if err == nil {
			t.Fatal("in-flight revoke reported success")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("local request did not terminate")
	}
	if calls.Load() != 1 || len(manager.PoolInFlightSnapshot()) != 0 {
		t.Fatal("model revoke replayed upstream or leaked a lease")
	}
}
