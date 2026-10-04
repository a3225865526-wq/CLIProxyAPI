package executor

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	coreexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
	sdktranslator "github.com/router-for-me/CLIProxyAPI/v8/sdk/translator"
)

func codexPoolFixture(t *testing.T, baseURL string, ws bool) (*coreauth.Manager, *coreauth.Auth) {
	t.Helper()
	root := t.TempDir()
	dir := filepath.Join(root, "auths")
	if os.Mkdir(dir, 0700) != nil {
		t.Fatal("fixture mkdir")
	}
	checkpoint := filepath.Join(root, "checkpoint.jsonl")
	policy := filepath.Join(root, "policy.json")
	t.Setenv("CLEARAPI_POOL_ROLE", "service")
	t.Setenv("CLEARAPI_POOL_EXECUTOR_ID", "synthetic-executor")
	t.Setenv("CLEARAPI_POOL_CHECKPOINT_FILE", checkpoint)
	t.Setenv("CLEARAPI_POOL_ADMISSION_FILE", policy)
	if err := coreauth.ProvisionPoolCheckpoint(checkpoint, "synthetic-executor"); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{AuthDir: dir}
	manager := coreauth.NewManager(nil, nil, nil)
	manager.SetConfig(cfg)
	if ws {
		manager.RegisterExecutor(NewCodexAutoExecutor(cfg))
	} else {
		manager.RegisterExecutor(NewCodexExecutor(cfg))
	}
	auth := &coreauth.Auth{ID: "synthetic-codex-pool", Provider: "codex", FileName: "synthetic.json", Status: coreauth.StatusActive, Attributes: map[string]string{coreauth.AttributeAuthKind: coreauth.AuthKindOAuth, "base_url": baseURL}, Metadata: map[string]any{"access_token": "synthetic-unused", "websockets": ws}}
	grant := coreauth.PoolGrantFile{GuardVersion: coreauth.PoolGuardVersion, ExecutorID: "synthetic-executor", Revision: 1, Grants: []coreauth.PoolGrant{{AuthID: auth.ID, Provider: auth.Provider, CredentialDigest: coreauth.PoolCredentialDigest(auth), Models: []string{"synthetic-native"}, Capabilities: []string{"text_chat", "stream_text", "exact_usage"}, Enabled: true, ExpiresAt: time.Now().Add(10 * time.Minute).Unix(), MaxConcurrency: 1, SourceEvidence: []string{"synthetic-source"}, TestEvidence: []string{"synthetic-test"}}}}
	data, _ := json.Marshal(grant)
	if err := os.WriteFile(policy, data, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Register(context.Background(), auth); err != nil {
		t.Fatal(err)
	}
	if err := manager.PromotePoolIdentities(context.Background(), coreauth.PoolPromotion{ExpectedRevision: 1, Identities: []coreauth.PoolIdentityExpectation{{AuthID: auth.ID, Provider: auth.Provider, CredentialDigest: coreauth.PoolCredentialDigest(auth)}}}); err != nil {
		t.Fatal(err)
	}
	registry.GetGlobalRegistry().RegisterClient(auth.ID, auth.Provider, []*registry.ModelInfo{{ID: "synthetic-native"}})
	t.Cleanup(func() { registry.GetGlobalRegistry().UnregisterClient(auth.ID) })
	return manager, auth
}

func revokeCodexPool(t *testing.T, manager *coreauth.Manager, auth *coreauth.Auth) {
	t.Helper()
	revision, states, err := manager.PoolTrustSnapshot()
	if err != nil || len(states) != 1 {
		t.Fatal("trust fixture", err)
	}
	if err := manager.RevokePoolIdentity(context.Background(), coreauth.PoolRevocation{ExpectedRevision: revision, Identity: coreauth.PoolIdentityExpectation{AuthID: auth.ID, Provider: auth.Provider, CredentialDigest: coreauth.PoolCredentialDigest(auth), Generation: states[0].Generation}}); err != nil {
		t.Fatal(err)
	}
}

func TestPoolStage1BCodexHTTPAndWebsocketHardRevoke(t *testing.T) {
	for _, kind := range []string{"http", "websocket"} {
		t.Run(kind, func(t *testing.T) {
			entered := make(chan struct{})
			finished := make(chan struct{})
			var calls atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				if kind == "http" {
					w.Header().Set("Content-Type", "text/event-stream")
					_, _ = w.Write([]byte("data: {\"type\":\"response.created\",\"response\":{\"id\":\"synthetic\"}}\n\n"))
					w.(http.Flusher).Flush()
					close(entered)
					<-r.Context().Done()
					close(finished)
					return
				}
				upgrader := websocket.Upgrader{}
				conn, err := upgrader.Upgrade(w, r, nil)
				if err != nil {
					return
				}
				defer conn.Close()
				if _, _, err := conn.ReadMessage(); err != nil {
					return
				}
				close(entered)
				// Hard revoke must close a retained websocket, not just abandon its reader.
				_, _, _ = conn.ReadMessage()
				close(finished)
			}))
			defer server.Close()
			manager, auth := codexPoolFixture(t, server.URL, kind == "websocket")
			manager.SetRetryConfig(3, 0, 3)
			result := make(chan error, 1)
			ctx, cancel := context.WithCancel(context.Background())
			if kind == "websocket" {
				ctx = coreexecutor.WithDownstreamWebsocket(ctx)
			}
			defer cancel()
			go func() {
				_, err := manager.Execute(ctx, []string{"codex"}, coreexecutor.Request{Model: "synthetic-native", Payload: []byte(`{"model":"synthetic-native","input":"synthetic"}`)}, coreexecutor.Options{SourceFormat: sdktranslator.FormatOpenAIResponse})
				result <- err
			}()
			select {
			case <-entered:
			case err := <-result:
				t.Fatal("request failed before synthetic upstream", err)
			case <-time.After(3 * time.Second):
				t.Fatal("no synthetic dispatch")
			}
			revokeCodexPool(t, manager, auth)
			select {
			case err := <-result:
				if !errors.Is(err, coreauth.ErrAccountRevoked) {
					t.Fatal("lost revoke reason", err)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("local request did not terminate")
			}
			select {
			case <-finished:
			case <-time.After(3 * time.Second):
				t.Fatal("upstream resource not closed")
			}
			if calls.Load() != 1 || len(manager.PoolInFlightSnapshot()) != 0 {
				t.Fatal("retry or lease leak")
			}
		})
	}
}

func TestPoolStage1BCodexHTTPPreDispatchRevoke(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1) }))
	defer server.Close()
	manager, auth := codexPoolFixture(t, server.URL, false)
	// This hook executes after selection, immediately before the provider is invoked.
	_, err := manager.Execute(context.Background(), []string{"codex"}, coreexecutor.Request{Model: "synthetic-native", Payload: []byte(`{"model":"synthetic-native","input":"synthetic"}`)}, coreexecutor.Options{SourceFormat: sdktranslator.FormatOpenAIResponse, RequestAfterAuthInterceptor: func(ctx context.Context, _ coreexecutor.RequestAfterAuthInterceptRequest) coreexecutor.RequestAfterAuthInterceptResponse {
		revokeCodexPool(t, manager, auth)
		return coreexecutor.RequestAfterAuthInterceptResponse{}
	}})
	if err == nil || calls.Load() != 0 || len(manager.PoolInFlightSnapshot()) != 0 {
		t.Fatal("revoked cached selection sent HTTP", err)
	}
}

type rejectPoolHandshake struct{}

func (rejectPoolHandshake) AuthorizeDispatch() error { return coreauth.ErrAccountRevoked }
func (rejectPoolHandshake) AuthorizeConnect() error  { return coreauth.ErrAccountRevoked }
func TestPoolStage1BWebsocketHandshakeFence(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1) }))
	defer server.Close()
	executor := NewCodexWebsocketsExecutor(&config.Config{})
	ctx := coreexecutor.WithDispatchGuard(context.Background(), rejectPoolHandshake{})
	_, _, _, err := executor.dialCodexWebsocket(ctx, &coreauth.Auth{}, "ws"+strings.TrimPrefix(server.URL, "http"), http.Header{})
	if !errors.Is(err, coreauth.ErrAccountRevoked) || calls.Load() != 0 {
		t.Fatal("revoked handshake sent credentials", err)
	}
}
