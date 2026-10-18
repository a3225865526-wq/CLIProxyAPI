package auth

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	internalconfig "github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
)

type poolProbeExecutor struct {
	calls    atomic.Int32
	stream   chan cliproxyexecutor.StreamChunk
	failure  bool
	unfenced bool
}

func TestStage74RetryReadsActualManagerAndOverride(t *testing.T) {
	m := NewManager(nil, nil, nil)
	m.SetRetryConfig(3, 7*time.Second, 2)
	m.auths["codex-real-test.json"] = &Auth{ID: "codex-real-test.json", Provider: "codex", Metadata: map[string]any{"type": "codex", "access_token": "stage74-secret-sentinel", "refresh_token": "stage74-secret-sentinel", "request_retry": 1}}
	value, err := m.RuntimeRetryDiagnostic()
	if err := err; err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(value)
	if err := err; err != nil {
		t.Fatal(err)
	}
	var projected map[string]any
	if err := json.Unmarshal(data, &projected); err != nil {
		t.Fatal(err)
	}
	if got := projected["global_request_retry"]; got != float64(3) {
		t.Errorf("unexpected diagnostic result: got %v, want %v", got, float64(3))
	}
	if got := projected["effective_request_retry"]; got != float64(1) {
		t.Errorf("unexpected diagnostic result: got %v, want %v", got, float64(1))
	}
	if got := projected["credential_retry_override"]; got != float64(1) {
		t.Errorf("unexpected diagnostic result: got %v, want %v", got, float64(1))
	}
	if got := projected["max_retry_interval_ms"]; got != float64(7000) {
		t.Errorf("unexpected diagnostic result: got %v, want %v", got, float64(7000))
	}
	if got := projected["at_most_one_provider_dispatch"]; got != false {
		t.Errorf("unexpected diagnostic result: got %v, want %v", got, false)
	}
	if strings.Contains(string(data), "stage74-secret-sentinel") {
		t.Fatal("secret leaked")
	}
	m.SetRetryConfig(0, 0, 1)
	delete(m.auths["codex-real-test.json"].Metadata, "request_retry")
	value, err = m.RuntimeRetryDiagnostic()
	if err := err; err != nil {
		t.Fatal(err)
	}
	data, err = json.Marshal(value)
	if err := err; err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &projected); err != nil {
		t.Fatal(err)
	}
	if got := projected["effective_request_retry"]; got != float64(0) {
		t.Errorf("unexpected diagnostic result: got %v, want %v", got, float64(0))
	}
	if got := projected["credential_retry_override_present"]; got != false {
		t.Errorf("unexpected diagnostic result: got %v, want %v", got, false)
	}
	if projected["credential_retry_override"] != nil {
		t.Fatal("unexpected credential retry override")
	}
	delete(m.auths, "codex-real-test.json")
	_, err = m.RuntimeRetryDiagnostic()
	if err == nil {
		t.Fatal("expected fail-closed error")
	}
}

// The zero value is fenced so unrelated fixtures keep their provider capability.
// Only an explicit unfenced probe models an executor that cannot fence dispatch.
func (e *poolProbeExecutor) PoolDispatchFencing() bool { return e != nil && !e.unfenced }
func (*poolProbeExecutor) Identifier() string          { return "codex" }

func TestPoolExecutorForwardsProviderDispatchFencing(t *testing.T) {
	manager := NewManager(nil, nil, nil)
	fenced := &poolExecutor{ProviderExecutor: &poolProbeExecutor{}, manager: manager}
	if !fenced.PoolDispatchFencing() {
		t.Fatal("fenced provider capability was not forwarded")
	}
	unfenced := &poolExecutor{ProviderExecutor: &poolProbeExecutor{unfenced: true}, manager: manager}
	if unfenced.PoolDispatchFencing() {
		t.Fatal("unfenced provider capability was promoted")
	}
	if (&poolExecutor{ProviderExecutor: struct{ ProviderExecutor }{}, manager: manager}).PoolDispatchFencing() {
		t.Fatal("executor without fencing capability was promoted")
	}
}
func (e *poolProbeExecutor) Execute(ctx context.Context, _ *Auth, _ cliproxyexecutor.Request, _ cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
	if err := cliproxyexecutor.BeforeUpstreamDispatch(ctx); err != nil {
		return cliproxyexecutor.Response{}, err
	}
	e.calls.Add(1)
	if e.failure {
		return cliproxyexecutor.Response{}, &Error{HTTPStatus: 500, Message: "synthetic failure"}
	}
	return cliproxyexecutor.Response{Payload: []byte(`{"usage":{"input_tokens":3,"output_tokens":4,"total_tokens":7}}`)}, nil
}
func (e *poolProbeExecutor) ExecuteStream(ctx context.Context, _ *Auth, _ cliproxyexecutor.Request, _ cliproxyexecutor.Options) (*cliproxyexecutor.StreamResult, error) {
	if err := cliproxyexecutor.BeforeUpstreamDispatch(ctx); err != nil {
		return nil, err
	}
	e.calls.Add(1)
	return &cliproxyexecutor.StreamResult{Chunks: e.stream}, nil
}
func (*poolProbeExecutor) Refresh(_ context.Context, a *Auth) (*Auth, error) { return a.Clone(), nil }
func (e *poolProbeExecutor) CountTokens(ctx context.Context, a *Auth, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
	return e.Execute(ctx, a, req, opts)
}
func (e *poolProbeExecutor) HttpRequest(context.Context, *Auth, *http.Request) (*http.Response, error) {
	e.calls.Add(1)
	return nil, nil
}

func poolGuardFixture(t *testing.T, role string, nativeTools ...bool) (*Manager, *poolProbeExecutor, *Auth, string, PoolGrantFile) {
	t.Helper()
	if os.Getenv("CLEARAPI_PG02_RESPONSES_SSE") != "true" {
		t.Setenv("CLEARAPI_PG02_HTTP_NON_STREAM", "true")
	}
	root := t.TempDir()
	dir := filepath.Join(root, "auths")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(root, "grants.json")
	checkpoint := filepath.Join(root, "checkpoint.jsonl")
	t.Setenv("CLEARAPI_POOL_ROLE", role)
	t.Setenv("CLEARAPI_POOL_ADMISSION_FILE", file)
	t.Setenv("CLEARAPI_POOL_EXECUTOR_ID", "synthetic-executor")
	t.Setenv("CLEARAPI_POOL_CHECKPOINT_FILE", checkpoint)
	if err := ProvisionPoolCheckpoint(checkpoint, "synthetic-executor"); err != nil {
		t.Fatal(err)
	}
	m := NewManager(nil, nil, nil)
	m.SetConfig(&internalconfig.Config{AuthDir: dir})
	executor := &poolProbeExecutor{stream: make(chan cliproxyexecutor.StreamChunk)}
	m.RegisterExecutor(executor)
	auth := &Auth{ID: "synthetic-pool-account", Provider: "codex", FileName: "synthetic-pool-account.json", Status: StatusActive, Attributes: map[string]string{AttributeAuthKind: AuthKindOAuth}, Metadata: map[string]any{"access_token": "synthetic-unused", "account_id": "synthetic-account-id", "email": "synthetic-pool-account@staging.invalid"}}
	record := PoolGrantFile{GuardVersion: PoolGuardVersion, Revision: 1, Grants: []PoolGrant{{AuthID: auth.ID, Provider: auth.Provider, CredentialDigest: PoolCredentialDigest(auth), Models: []string{"synthetic-native"}, Capabilities: []string{"text_chat", "stream_text", "exact_usage"}, Enabled: true, MaxConcurrency: 1, ExpiresAt: time.Now().Add(10 * time.Minute).Unix(), SourceEvidence: []string{"synthetic-source"}, TestEvidence: []string{"synthetic-test"}}}}
	record.ExecutorID = "synthetic-executor"
	if len(nativeTools) != 0 && nativeTools[0] {
		record.Grants[0].Capabilities = append(record.Grants[0].Capabilities, "tools")
		record.Grants[0].NativeTools = true
	}
	writePoolGrant(t, file, record)
	registered, err := m.Register(context.Background(), auth)
	if err != nil {
		t.Fatal(err)
	}
	if role == "service" {
		err := m.PromotePoolIdentities(context.Background(), PoolPromotion{ExpectedRevision: record.Revision, Identities: []PoolIdentityExpectation{{AuthID: auth.ID, Provider: auth.Provider, CredentialDigest: PoolCredentialDigest(auth)}}})
		if err != nil {
			t.Fatal(err)
		}
		record.Revision++
		if err := grantPoolModelCapability(t, m, auth, record.Grants[0].Models[0]); err != nil {
			t.Fatal(err)
		}
		record.Revision++
		record.Capabilities = []PoolModelCapability{{AuthID: auth.ID, Provider: auth.Provider, CredentialDigest: PoolCredentialDigest(auth), Model: record.Grants[0].Models[0], State: PoolCapabilityVerified, Generation: record.Revision - 1}}
		registered, _ = m.GetByID(auth.ID)
	}
	registry.GetGlobalRegistry().RegisterClient(auth.ID, auth.Provider, []*registry.ModelInfo{{ID: "synthetic-native"}, {ID: "synthetic-other"}})
	t.Cleanup(func() { registry.GetGlobalRegistry().UnregisterClient(auth.ID) })
	return m, executor, registered, file, record
}

func writePoolGrant(t *testing.T, file string, record PoolGrantFile) {
	t.Helper()
	body, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, body, 0600); err != nil {
		t.Fatal(err)
	}
}

// grantPoolModelCapability exercises the STEP 3 grant command for one model.
func grantPoolModelCapability(t *testing.T, m *Manager, auth *Auth, model string) error {
	t.Helper()
	revision, states, err := m.PoolTrustSnapshot()
	if err != nil {
		t.Fatal(err)
	}
	identity := PoolIdentityExpectation{AuthID: auth.ID, Provider: auth.Provider, CredentialDigest: PoolCredentialDigest(auth)}
	for _, state := range states {
		if state.AuthID == auth.ID {
			identity.Generation = state.Generation
		}
	}
	return m.GrantPoolModelCapability(context.Background(), PoolModelGrant{ExpectedRevision: revision, Identity: identity, Model: model})
}

// revokePoolModelCapability exercises the STEP 3 revoke command for one model.
func revokePoolModelCapability(t *testing.T, m *Manager, auth *Auth, model string) error {
	t.Helper()
	revision, states, err := m.PoolTrustSnapshot()
	if err != nil {
		t.Fatal(err)
	}
	identity := PoolIdentityExpectation{AuthID: auth.ID, Provider: auth.Provider, CredentialDigest: PoolCredentialDigest(auth)}
	for _, state := range states {
		if state.AuthID == auth.ID {
			identity.Generation = state.Generation
		}
	}
	return m.RevokePoolModelCapability(context.Background(), PoolModelRevoke{ExpectedRevision: revision, Identity: identity, Model: model})
}

func TestPoolGuardStagingAndUnknownRoleNeverExecute(t *testing.T) {
	for _, role := range []string{"staging", "typo"} {
		t.Run(role, func(t *testing.T) {
			m, executor, auth, _, _ := poolGuardFixture(t, role)
			if !auth.Disabled || auth.Status != StatusDisabled || auth.Metadata["disabled"] != true {
				t.Fatal("new auth was not quarantined")
			}
			_, err := m.Execute(context.Background(), []string{"codex"}, cliproxyexecutor.Request{Model: "synthetic-native"}, cliproxyexecutor.Options{})
			if err == nil || executor.calls.Load() != 0 {
				t.Fatal("staging/unknown role executed upstream")
			}
			_, err = m.ExecuteStream(context.Background(), []string{"codex"}, cliproxyexecutor.Request{Model: "synthetic-native"}, cliproxyexecutor.Options{Stream: true})
			if err == nil || executor.calls.Load() != 0 {
				t.Fatal("staging streamed upstream")
			}
		})
	}
}

func TestPoolGuardCandidateAndSendRecheck(t *testing.T) {
	m, executor, auth, file, record := poolGuardFixture(t, "service")
	if auth.Disabled {
		t.Fatal("synthetic trusted grant was not loaded")
	}
	_, err := m.Execute(context.Background(), []string{"codex"}, cliproxyexecutor.Request{Model: "synthetic-native"}, cliproxyexecutor.Options{})
	if err != nil || executor.calls.Load() != 1 {
		t.Fatalf("admitted request: error=%v calls=%d", err, executor.calls.Load())
	}
	for _, body := range []string{`{"tools":[{"type":"function"}]}`, `{"messages":[{"content":[{"type":"image","source":{}}]}]}`, `{"messages":[{"role":"tool","content":"synthetic"}]}`, `{"input":[{"type":"function_call_output","output":"synthetic"}]}`, `{"messages":[{"content":[{"type":"tool_result","content":"synthetic"}]}]}`} {
		_, err = m.Execute(context.Background(), []string{"codex"}, cliproxyexecutor.Request{Model: "synthetic-native", Payload: []byte(body)}, cliproxyexecutor.Options{OriginalRequest: []byte(body)})
		if err == nil || executor.calls.Load() != 1 {
			t.Fatal("unadmitted request capability executed")
		}
	}
	_, err = m.Execute(context.Background(), []string{"codex"}, cliproxyexecutor.Request{Model: "synthetic-other"}, cliproxyexecutor.Options{})
	if err == nil || executor.calls.Load() != 1 {
		t.Fatal("other model executed")
	}
	// A selected credential snapshot cannot bypass a grant removed before send.
	wrapped, _ := m.Executor("codex")
	ctx, err := m.poolExecutionContext(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	record.Revision++
	record.Grants = nil
	writePoolGrant(t, file, record)
	_, err = wrapped.Execute(ctx, auth, cliproxyexecutor.Request{Model: "synthetic-native"}, cliproxyexecutor.Options{})
	if err == nil || executor.calls.Load() != 1 {
		t.Fatal("revoked selection snapshot executed")
	}
	_, err = wrapped.HttpRequest(context.Background(), auth, &http.Request{})
	if err == nil || executor.calls.Load() != 1 {
		t.Fatal("raw credentialed HTTP bypass executed")
	}
	if err := m.InjectCredentials(&http.Request{}, auth.ID); err == nil {
		t.Fatal("raw credential injection silently succeeded")
	}
	if err := m.PrepareHttpRequest(context.Background(), auth, &http.Request{}); err == nil {
		t.Fatal("raw credential preparation succeeded")
	}
}

func TestPoolGuardRejectsManifestFailuresAndCredentialChange(t *testing.T) {
	for _, scenario := range []string{"expired", "wrong-digest", "duplicate", "missing-evidence", "old-version", "inside-auth-dir", "corrupt"} {
		t.Run(scenario, func(t *testing.T) {
			m, executor, _, file, record := poolGuardFixture(t, "service")
			record.Revision++
			switch scenario {
			case "expired":
				record.Grants[0].ExpiresAt = time.Now().Add(-time.Minute).Unix()
			case "wrong-digest":
				record.Grants[0].CredentialDigest = "different"
			case "duplicate":
				record.Grants = append(record.Grants, record.Grants[0])
			case "missing-evidence":
				record.Grants[0].TestEvidence = nil
			case "old-version":
				record.GuardVersion++
			case "inside-auth-dir":
				m.poolGuard.file = filepath.Join(m.runtimeConfigSnapshot().AuthDir, "grants.json")
				file = m.poolGuard.file
			}
			if scenario == "corrupt" {
				if err := os.WriteFile(file, []byte("{"), 0600); err != nil {
					t.Fatal(err)
				}
			} else {
				writePoolGrant(t, file, record)
			}
			_, err := m.Execute(context.Background(), []string{"codex"}, cliproxyexecutor.Request{Model: "synthetic-native"}, cliproxyexecutor.Options{})
			if err == nil || executor.calls.Load() != 0 {
				t.Fatal("invalid grant executed upstream")
			}
		})
	}
}

func TestPoolGuardRefreshPauseAndRestartPreserveQuarantine(t *testing.T) {
	m, executor, auth, file, record := poolGuardFixture(t, "service")
	revision, trustBefore, err := m.PoolTrustSnapshot()
	if err != nil || len(trustBefore) != 1 {
		t.Fatal("trust baseline unavailable", err)
	}
	// Token rotation while active retains authorization without promotion.
	rotated := auth.Clone()
	rotated.Metadata["access_token"] = "synthetic-rotated"
	rotated, err = m.Update(context.Background(), rotated)
	if err != nil || rotated.Disabled {
		t.Fatal("active token rotation churned trust", err)
	}
	if err := poolRequest(m); err != nil || executor.calls.Load() != 1 {
		t.Fatal("active token rotation broke trusted admission", err)
	}
	auth = rotated
	auth.Disabled = true
	paused, err := m.Update(context.Background(), auth)
	if err != nil {
		t.Fatal(err)
	}
	refreshed := paused.Clone()
	refreshed.Disabled = false
	refreshed.Status = StatusActive
	updated, err := m.UpdateRefreshedAuth(context.Background(), paused, refreshed)
	if err != nil || !updated.Disabled {
		t.Fatal("refresh unpaused auth")
	}
	_, err = m.Execute(context.Background(), []string{"codex"}, cliproxyexecutor.Request{Model: "synthetic-native"}, cliproxyexecutor.Options{})
	if err == nil || executor.calls.Load() != 1 {
		t.Fatal("paused auth executed")
	}
	// Stable trust never authorizes clearing a separate management isolation.
	rotated = updated.Clone()
	rotated.Disabled = false
	rotated.Status = StatusActive
	rotated.Metadata["access_token"] = "synthetic-rotated"
	rotated, err = m.Update(context.Background(), rotated)
	if err != nil || !rotated.Disabled || !ManagementIsolation(rotated) {
		t.Fatal("token rotation cleared management isolation", err)
	}
	revisionAfter, trustAfter, err := m.PoolTrustSnapshot()
	if err != nil || revisionAfter != revision || len(trustAfter) != 1 || trustAfter[0] != trustBefore[0] {
		t.Fatal("stable token rotation changed trust revision or generation", err)
	}
	if poolRequest(m) == nil || executor.calls.Load() != 1 {
		t.Fatal("isolated token rotation dispatched")
	}
	// Replacing the stable account identity is a credential replacement. It can
	// never self-admit — not with the same auth ID, file name, or metadata claim.
	changed := updated.Clone()
	changed.Disabled = false
	changed.Status = StatusActive
	changed.Metadata["account_id"] = "synthetic-account-id-replaced"
	changed.Metadata["pool_admitted"] = true
	changed, err = m.Update(context.Background(), changed)
	if err != nil || !changed.Disabled {
		t.Fatal("changed credential self-admitted")
	}
	record.Revision++
	record.Grants[0].Enabled = false
	writePoolGrant(t, file, record)
	restarted := NewManager(nil, nil, nil)
	restarted.SetConfig(m.runtimeConfigSnapshot())
	restarted.RegisterExecutor(executor)
	_, err = restarted.Register(context.Background(), changed)
	if err != nil {
		t.Fatal(err)
	}
	callsBeforeRestart := executor.calls.Load()
	_, err = restarted.Execute(context.Background(), []string{"codex"}, cliproxyexecutor.Request{Model: "synthetic-native"}, cliproxyexecutor.Options{})
	if err == nil || executor.calls.Load() != callsBeforeRestart {
		t.Fatal("restart reopened quarantined auth")
	}
}

func TestPoolGuardStreamConcurrencyAndSingleAttempt(t *testing.T) {
	m, executor, _, _, _ := poolGuardFixture(t, "service")
	executor.stream = make(chan cliproxyexecutor.StreamChunk, 1)
	executor.stream <- cliproxyexecutor.StreamChunk{Payload: []byte("data: {\"type\":\"response.output_text.delta\",\"delta\":\"synthetic\"}\n\n")}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result, err := m.ExecuteStream(ctx, []string{"codex"}, cliproxyexecutor.Request{Model: "synthetic-native"}, cliproxyexecutor.Options{Stream: true})
	if err != nil {
		t.Fatal(err)
	}
	_, err = m.Execute(context.Background(), []string{"codex"}, cliproxyexecutor.Request{Model: "synthetic-native"}, cliproxyexecutor.Options{})
	if err == nil || executor.calls.Load() != 1 {
		t.Fatal("stream concurrency was released before stream end")
	}
	cancel()
	for range result.Chunks {
	}
	deadline := time.Now().Add(time.Second)
	for {
		m.poolGuard.countsMu.Lock()
		active := m.poolGuard.counts["synthetic-pool-account"]
		m.poolGuard.countsMu.Unlock()
		if active == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("stream cancellation leaked concurrency")
		}
		time.Sleep(time.Millisecond)
	}
	executor.failure = true
	m.SetRetryConfig(3, 0, 3)
	_, err = m.Execute(context.Background(), []string{"codex"}, cliproxyexecutor.Request{Model: "synthetic-native"}, cliproxyexecutor.Options{})
	if err == nil || executor.calls.Load() != 2 {
		t.Fatalf("unsafe retry executed: calls=%d", executor.calls.Load())
	}
}
