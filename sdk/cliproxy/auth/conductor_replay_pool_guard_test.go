package auth

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	internalconfig "github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
)

type replayPoolTransport struct {
	calls         atomic.Int32
	mu            sync.Mutex
	accounts      []string
	failureAuth   string
	budget        *atomicPoolAttempt
	executorCalls atomic.Int32
	manager       *Manager
}

func (*replayPoolTransport) Identifier() string        { return "codex" }
func (*replayPoolTransport) PoolDispatchFencing() bool { return true }

func (e *replayPoolTransport) Execute(ctx context.Context, auth *Auth, _ cliproxyexecutor.Request, _ cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
	e.executorCalls.Add(1)
	if err := cliproxyexecutor.BeforeUpstreamDispatch(ctx); err != nil {
		return cliproxyexecutor.Response{}, err
	}
	cliproxyexecutor.MarkUpstreamAttempt(ctx)
	e.budget, _ = ctx.Value(poolAttemptContextKey{}).(*atomicPoolAttempt)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://synthetic.invalid/responses", nil)
	if err != nil {
		return cliproxyexecutor.Response{}, err
	}
	req.Header.Set("Synthetic-Account", auth.ID)
	if e.manager == nil {
		return cliproxyexecutor.Response{}, errors.New("synthetic manager missing")
	}
	roundTripper := e.manager.roundTripperFor(auth)
	if roundTripper == nil {
		return cliproxyexecutor.Response{}, errors.New("synthetic round tripper missing")
	}
	response, err := roundTripper.RoundTrip(req)
	if err != nil {
		return cliproxyexecutor.Response{}, err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		return cliproxyexecutor.Response{}, err
	}
	if response.StatusCode != http.StatusOK {
		return cliproxyexecutor.Response{}, &Error{HTTPStatus: response.StatusCode, Message: string(body)}
	}
	return cliproxyexecutor.Response{Payload: body}, nil
}

// RoundTrip is the actual synthetic provider transport entrance, not selection
// or admission. It never opens a network connection or uses real credentials.
func (e *replayPoolTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	accountID := req.Header.Get("Synthetic-Account")
	e.calls.Add(1)
	e.mu.Lock()
	e.accounts = append(e.accounts, accountID)
	e.mu.Unlock()
	status := http.StatusOK
	body := `{"usage":{"input_tokens":1,"output_tokens":1,"total_tokens":2}}`
	if accountID == e.failureAuth {
		status = http.StatusBadRequest
		body = "ordinary provider 400"
	}
	return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body)), Request: req}, nil
}

func (e *replayPoolTransport) RoundTripperFor(*Auth) http.RoundTripper { return e }

func (*replayPoolTransport) ExecuteStream(context.Context, *Auth, cliproxyexecutor.Request, cliproxyexecutor.Options) (*cliproxyexecutor.StreamResult, error) {
	return nil, ErrPoolGuard
}
func (*replayPoolTransport) Refresh(_ context.Context, auth *Auth) (*Auth, error) {
	return auth.Clone(), nil
}
func (e *replayPoolTransport) CountTokens(ctx context.Context, auth *Auth, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
	return e.Execute(ctx, auth, req, opts)
}
func (*replayPoolTransport) HttpRequest(context.Context, *Auth, *http.Request) (*http.Response, error) {
	return nil, ErrPoolGuard
}

func (e *replayPoolTransport) accountCalls() []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]string(nil), e.accounts...)
}

func TestPoolGuardOrdinary400StopsBeforeSecondAccount(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "auths")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(root, "grants.json")
	checkpoint := filepath.Join(root, "checkpoint.jsonl")
	t.Setenv("CLEARAPI_POOL_ROLE", "service")
	t.Setenv("CLEARAPI_POOL_ADMISSION_FILE", file)
	t.Setenv("CLEARAPI_POOL_EXECUTOR_ID", "synthetic-replay-executor")
	t.Setenv("CLEARAPI_POOL_CHECKPOINT_FILE", checkpoint)
	if err := ProvisionPoolCheckpoint(checkpoint, "synthetic-replay-executor"); err != nil {
		t.Fatal(err)
	}
	m := NewManager(nil, nil, nil)
	m.SetConfig(&internalconfig.Config{AuthDir: dir})
	first := &Auth{ID: "replay-pool-a", Provider: "codex", Status: StatusActive, Attributes: map[string]string{AttributeAuthKind: AuthKindOAuth}, Metadata: map[string]any{"access_token": "synthetic-a", "account_id": "synthetic-a", "email": "a@synthetic.invalid"}}
	second := &Auth{ID: "replay-pool-b", Provider: "codex", Status: StatusActive, Attributes: map[string]string{AttributeAuthKind: AuthKindOAuth}, Metadata: map[string]any{"access_token": "synthetic-b", "account_id": "synthetic-b", "email": "b@synthetic.invalid"}}
	record := PoolGrantFile{GuardVersion: PoolGuardVersion, ExecutorID: "synthetic-replay-executor", Revision: 1}
	for _, account := range []*Auth{first, second} {
		record.Grants = append(record.Grants, PoolGrant{AuthID: account.ID, Provider: account.Provider, CredentialDigest: PoolCredentialDigest(account), Models: []string{"synthetic-native"}, Capabilities: []string{"text_chat", "stream_text", "exact_usage"}, Enabled: true, MaxConcurrency: 1, ExpiresAt: time.Now().Add(10 * time.Minute).Unix(), SourceEvidence: []string{"synthetic-source"}, TestEvidence: []string{"synthetic-test"}})
	}
	writePoolGrant(t, file, record)
	transport := &replayPoolTransport{failureAuth: first.ID}
	transport.manager = m
	m.SetRoundTripperProvider(transport)
	m.RegisterExecutor(transport)
	for _, account := range []*Auth{first, second} {
		if _, err := m.Register(context.Background(), account); err != nil {
			t.Fatal(err)
		}
	}
	if err := m.PromotePoolIdentities(context.Background(), PoolPromotion{
		ExpectedRevision: record.Revision,
		Identities:       []PoolIdentityExpectation{{AuthID: first.ID, Provider: first.Provider, CredentialDigest: PoolCredentialDigest(first)}, {AuthID: second.ID, Provider: second.Provider, CredentialDigest: PoolCredentialDigest(second)}},
	}); err != nil {
		t.Fatal(err)
	}
	for _, account := range []*Auth{first, second} {
		if err := grantPoolModelCapability(t, m, account, "synthetic-native"); err != nil {
			t.Fatal(err)
		}
		registry.GetGlobalRegistry().RegisterClient(account.ID, account.Provider, []*registry.ModelInfo{{ID: "synthetic-native"}})
		id := account.ID
		t.Cleanup(func() { registry.GetGlobalRegistry().UnregisterClient(id) })
	}
	for _, account := range []*Auth{first, second} {
		current, ok := m.GetByID(account.ID)
		if !ok || !m.poolCandidateAllowed(current, "synthetic-native", cliproxyexecutor.Options{}) {
			t.Fatalf("synthetic account %s must be genuinely eligible", account.ID)
		}
	}
	m.SetRetryConfig(3, 30*time.Second, 3)
	if addressFile := os.Getenv("PG02_POOL_BRIDGE_ADDRESS_FILE"); addressFile != "" {
		mux := http.NewServeMux()
		mux.HandleFunc("/v1/chat/completions", func(w http.ResponseWriter, req *http.Request) {
			_, failure := m.Execute(req.Context(), []string{"codex"}, cliproxyexecutor.Request{Model: "synthetic-native"}, cliproxyexecutor.Options{})
			if failure == nil {
				w.WriteHeader(500)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(statusCodeFromError(failure))
			_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]any{"code": "model_not_found", "message": "synthetic dispatched provider 400"}})
		})
		mux.HandleFunc("/counts", func(w http.ResponseWriter, _ *http.Request) {
			accounts := transport.accountCalls()
			a, b := 0, 0
			for _, id := range accounts {
				if id == first.ID {
					a++
				}
				if id == second.ID {
					b++
				}
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"A": a, "B": b, "total": transport.calls.Load(), "executor_calls": transport.executorCalls.Load(), "budget_consumed": transport.budget != nil && transport.budget.Load()})
		})
		server := httptest.NewServer(mux)
		defer server.Close()
		if err := os.WriteFile(addressFile, []byte(server.URL), 0600); err != nil {
			t.Fatal(err)
		}
		select {}
	}
	_, err := m.Execute(context.Background(), []string{"codex"}, cliproxyexecutor.Request{Model: "synthetic-native"}, cliproxyexecutor.Options{})
	if err == nil {
		t.Fatal("ordinary dispatched 400 must stop transparent replay")
	}
	accounts := transport.accountCalls()
	if len(accounts) != 1 || accounts[0] != first.ID {
		t.Fatalf("execute error=%v; provider transport accounts = %v, want only account A", err, accounts)
	}
	if got := transport.calls.Load(); got != 1 {
		t.Fatalf("provider transport entries = %d, want 1", got)
	}
	if statusCodeFromError(err) != 400 || IsLocalPoolSelectionError(err) || IsLocalModelResolutionError(err) {
		t.Fatalf("provider error was replaced by zero-dispatch provenance: %v", err)
	}
	if transport.executorCalls.Load() != 1 || transport.budget == nil || !transport.budget.Load() {
		t.Fatal("outer retry occurred or consumed attempt budget was reset")
	}
	t.Logf("synthetic provider transport entries: A=1 B=0 total=1; final_status=%d retry_config=3", statusCodeFromError(err))
}
