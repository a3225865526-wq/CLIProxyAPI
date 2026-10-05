package executor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
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
	auth := &coreauth.Auth{ID: "synthetic-codex-pool", Provider: "codex", FileName: "synthetic.json", Status: coreauth.StatusActive, Attributes: map[string]string{coreauth.AttributeAuthKind: coreauth.AuthKindOAuth, "base_url": baseURL}, Metadata: map[string]any{"access_token": "synthetic-unused", "websockets": ws, "account_id": "synthetic-account-id"}}
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
	revision, states, err := manager.PoolTrustSnapshot()
	if err != nil || len(states) != 1 {
		t.Fatal("trust fixture", err)
	}
	if err := manager.GrantPoolModelCapability(context.Background(), coreauth.PoolModelGrant{ExpectedRevision: revision, Identity: coreauth.PoolIdentityExpectation{AuthID: auth.ID, Provider: auth.Provider, CredentialDigest: coreauth.PoolCredentialDigest(auth), Generation: states[0].Generation}, Model: "synthetic-native"}); err != nil {
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

func TestCodexMeteringPoolHTTPAndWebsocket(t *testing.T) {
	const final = `{"type":"response.completed","response":{"id":"synthetic-stage2","model":"synthetic-native","status":"completed","output":[],"usage":{"input_tokens":100,"output_tokens":20,"total_tokens":120,"input_tokens_details":{"cached_tokens":30},"output_tokens_details":{"reasoning_tokens":7}}}}`
	for _, kind := range []string{"http", "websocket"} {
		for _, stream := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/stream=%t", kind, stream), func(t *testing.T) {
				var calls atomic.Int32
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					calls.Add(1)
					if kind == "http" {
						w.Header().Set("Content-Type", "text/event-stream")
						_, _ = fmt.Fprintf(w, "data: %s\n\n", final)
						return
					}
					conn, err := (&websocket.Upgrader{}).Upgrade(w, r, nil)
					if err != nil {
						return
					}
					defer conn.Close()
					if _, _, err = conn.ReadMessage(); err == nil {
						_ = conn.WriteMessage(websocket.TextMessage, []byte(final))
					}
				}))
				defer server.Close()
				manager, _ := codexPoolFixture(t, server.URL, kind == "websocket")
				ctx := context.Background()
				if kind == "websocket" {
					ctx = coreexecutor.WithDownstreamWebsocket(ctx)
				}
				req := coreexecutor.Request{Model: "synthetic-native", Payload: []byte(`{"model":"synthetic-native","input":"synthetic"}`)}
				opts := coreexecutor.Options{SourceFormat: sdktranslator.FormatOpenAIResponse, Headers: http.Header{"X-Codex-Metering": {"v1"}}}
				var body []byte
				if stream {
					result, err := manager.ExecuteStream(ctx, []string{"codex"}, req, opts)
					if err != nil {
						t.Fatal(err)
					}
					for chunk := range result.Chunks {
						if chunk.Err != nil {
							t.Fatal(chunk.Err)
						}
						body = append(body, chunk.Payload...)
					}
				} else {
					result, err := manager.Execute(ctx, []string{"codex"}, req, opts)
					if err != nil {
						t.Fatal(err)
					}
					body = result.Payload
				}
				if !strings.Contains(string(body), `"status":"exact"`) || !strings.Contains(string(body), `"cached_input_tokens":30`) || !strings.Contains(string(body), `"reasoning_tokens":7`) {
					t.Fatalf("lost authoritative usage: %s", body)
				}
				if calls.Load() != 1 || len(manager.PoolInFlightSnapshot()) != 0 {
					t.Fatal("replay or lease leak")
				}
			})
		}
	}
}

const codexPoolStage2Final = `{"type":"response.completed","response":{"id":"synthetic-stage2","status":"completed","output":[],"usage":{"input_tokens":100,"output_tokens":20,"total_tokens":120,"input_tokens_details":{"cached_tokens":30},"output_tokens_details":{"reasoning_tokens":7}}}}`

// codexMeteringAfterTerminalServer serves one Codex turn whose terminal usage
// event is followed by either an immediate connection close or a stall, so both
// the EOF race and the interrupted-stream path stay deterministic.
func codexMeteringAfterTerminalServer(t *testing.T, kind string, stream bool, closeAfterTerminal bool) (*httptest.Server, <-chan struct{}) {
	t.Helper()
	terminalSent := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if kind == "http" {
			w.Header().Set("Content-Type", "text/event-stream")
			_, _ = fmt.Fprintf(w, "data: %s\n\n", codexPoolStage2Final)
			if stream {
				w.(http.Flusher).Flush()
			}
			close(terminalSent)
			if !closeAfterTerminal {
				<-r.Context().Done()
			}
			return
		}
		conn, errUpgrade := (&websocket.Upgrader{}).Upgrade(w, r, nil)
		if errUpgrade != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		if _, _, errRead := conn.ReadMessage(); errRead != nil {
			return
		}
		_ = conn.WriteMessage(websocket.TextMessage, []byte(codexPoolStage2Final))
		close(terminalSent)
		if !closeAfterTerminal {
			_, _, _ = conn.ReadMessage()
		}
	}))
	t.Cleanup(server.Close)
	return server, terminalSent
}

// An upstream that closes right after its terminal usage event must not have that
// event cancelled by the read loop's own disconnect handling.
func TestCodexMeteringSurvivesTerminalCloseRace(t *testing.T) {
	for _, kind := range []string{"http", "websocket"} {
		for _, stream := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/stream=%t", kind, stream), func(t *testing.T) {
				server, terminalSent := codexMeteringAfterTerminalServer(t, kind, stream, true)
				manager, _ := codexPoolFixture(t, server.URL, kind == "websocket")
				ctx := context.Background()
				if kind == "websocket" {
					ctx = coreexecutor.WithDownstreamWebsocket(ctx)
				}
				req := coreexecutor.Request{Model: "synthetic-native", Payload: []byte(`{"model":"synthetic-native","input":"synthetic"}`)}
				opts := coreexecutor.Options{SourceFormat: sdktranslator.FormatOpenAIResponse, Headers: http.Header{"X-Codex-Metering": {"v1"}}}
				var body []byte
				if stream {
					result, err := manager.ExecuteStream(ctx, []string{"codex"}, req, opts)
					if err != nil {
						t.Fatal(err)
					}
					for chunk := range result.Chunks {
						if chunk.Err != nil {
							t.Fatal(chunk.Err)
						}
						body = append(body, chunk.Payload...)
					}
				} else {
					result, err := manager.Execute(ctx, []string{"codex"}, req, opts)
					if err != nil {
						t.Fatal(err)
					}
					body = result.Payload
				}
				<-terminalSent
				if !strings.Contains(string(body), `"status":"exact"`) || !strings.Contains(string(body), `"cached_input_tokens":30`) {
					t.Fatalf("terminal close discarded authoritative usage: %s", body)
				}
				if len(manager.PoolInFlightSnapshot()) != 0 {
					t.Fatal("lease leak after terminal close")
				}
			})
		}
	}
}

// An upstream that ends without any authoritative usage must be reported as
// unavailable, never as an exact zero bill.
func TestCodexMeteringMissingFinalIsUnavailable(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte("data: {\"type\":\"response.created\",\"response\":{\"id\":\"synthetic\"}}\n\n"))
		w.(http.Flusher).Flush()
	}))
	defer server.Close()
	manager, _ := codexPoolFixture(t, server.URL, false)
	request := coreexecutor.Request{Model: "synthetic-native", Payload: []byte(`{"model":"synthetic-native","input":"synthetic"}`)}
	opts := coreexecutor.Options{SourceFormat: sdktranslator.FormatOpenAIResponse, Headers: http.Header{"X-Codex-Metering": {"v1"}}}
	result, errStream := manager.ExecuteStream(context.Background(), []string{"codex"}, request, opts)
	var body []byte
	if errStream != nil {
		t.Fatal(errStream)
	}
	for chunk := range result.Chunks {
		if chunk.Err != nil {
			break
		}
		body = append(body, chunk.Payload...)
	}
	if calls.Load() != 1 {
		t.Fatalf("synthetic upstream calls = %d, want 1", calls.Load())
	}
	if strings.Contains(string(body), `"status":"exact"`) {
		t.Fatalf("missing final usage was reported as exact: %s", body)
	}
	// Releasing the lease happens on the stream owner's goroutine, so asserting
	// the registry is empty must tolerate that bounded handoff.
	if !waitForEmptyPoolLeases(manager, 3*time.Second) {
		t.Fatalf("lease leak after interrupted stream: %+v", manager.PoolInFlightSnapshot())
	}
}

// waitForEmptyPoolLeases reports whether the in-flight registry drained within
// the bound, so a leaked lease still fails while a lagging release does not.
func waitForEmptyPoolLeases(manager *coreauth.Manager, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for {
		if len(manager.PoolInFlightSnapshot()) == 0 {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(2 * time.Millisecond)
	}
}

// A revoke that lands after the terminal usage event still settles exactly once
// with the receipt the lease observed, instead of inventing usage or replaying.
func TestCodexMeteringRevokeAfterTerminalKeepsExactReceipt(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = fmt.Fprintf(w, "data: %s\n\n", codexPoolStage2Final)
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	}))
	defer server.Close()
	manager, auth := codexPoolFixture(t, server.URL, false)
	manager.SetRetryConfig(3, 0, 3)
	result := make(chan error, 1)
	go func() {
		_, err := manager.Execute(context.Background(), []string{"codex"}, coreexecutor.Request{Model: "synthetic-native", Payload: []byte(`{"model":"synthetic-native","input":"synthetic"}`)}, coreexecutor.Options{SourceFormat: sdktranslator.FormatOpenAIResponse, Headers: http.Header{"X-Codex-Metering": {"v1"}}})
		result <- err
	}()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if len(manager.PoolInFlightSnapshot()) != 0 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	revokeCodexPool(t, manager, auth)
	select {
	case err := <-result:
		if err != nil && !errors.Is(err, coreauth.ErrAccountRevoked) {
			t.Fatalf("unexpected revoke outcome: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("local request did not terminate")
	}
	if calls.Load() != 1 || len(manager.PoolInFlightSnapshot()) != 0 {
		t.Fatal("revoke replayed upstream or leaked a lease")
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
