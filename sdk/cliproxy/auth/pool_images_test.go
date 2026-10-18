package auth

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
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

// TestPG03ImagesControlledSingleImage covers the executor-side Images Contract
// v1: a signed single-image request executes once and publishes exactly one
// schema-3 FINAL receipt after its payload is durable; missing capability
// evidence, an unsigned request, a base-model mismatch, an unsupported count, a
// storage failure and a zero-image result all prevent a success publication.
func TestPG03ImagesControlledSingleImage(t *testing.T) {
	t.Setenv("CLEARAPI_PG02_RESPONSES_SSE", "")
	t.Setenv("CLEARAPI_PG02_HTTP_NON_STREAM", "")
	t.Setenv("CLEARAPI_PG03_IMAGES", "true")
	t.Setenv("CLEARAPI_PG03_IMAGES_POLICY_KEY", "synthetic-images-policy-key-012345678901234567890123")
	t.Setenv("CLEARAPI_PG02_PROCESS_EPOCH", "00112233445566778899aabbccddeeff")
	t.Setenv("CLEARAPI_PG02_GATEWAY_PROOF_KEY", "synthetic-proof-key-for-local-unit-tests-only")

	for _, scenario := range []string{"success", "no-capability", "unsigned", "base-model-mismatch", "n-not-one", "result-storage-failure", "no-image-output"} {
		t.Run(scenario, func(t *testing.T) {
			fixture := newImagesFixture(t, scenario)
			payload := []byte(`{"model":"gpt-image-2","prompt":"a cat","n":1,"size":"1024x1024"}`)
			opts := cliproxyexecutor.Options{
				OriginalRequest: payload,
				Headers:         http.Header{},
				Metadata:        map[string]any{cliproxyexecutor.RequestPathMetadataKey: "/v1/images/generations"},
			}
			opts.Headers.Set(pg03ImagesRequestHeader, "images-request")
			opts.Headers.Set(pg03ImagesAttemptHeader, "images-attempt")
			if scenario == "unsigned" {
				// No policy headers at all: the pool must classify this as a
				// non-images request instead of an authorized images operation.
				opts.Headers = http.Header{}
			} else {
				signImagesPolicy(t, opts.Headers, payload, scenario)
			}
			if scenario == "n-not-one" {
				opts.OriginalRequest = []byte(`{"model":"gpt-image-2","prompt":"a cat","n":2}`)
				signImagesPolicy(t, opts.Headers, opts.OriginalRequest, scenario)
			}
			ctx := context.WithValue(context.Background(), poolAttemptContextKey{}, &atomicPoolAttempt{})

			policy, ids, errPolicy := fixture.manager.verifyPG03ImagesPolicy(ctx, []string{"codex"}, opts)
			if scenario == "unsigned" {
				if errPolicy != nil || policy != nil || len(ids) != 0 {
					t.Fatalf("unsigned request must not produce an images policy: policy=%v ids=%v err=%v", policy, ids, errPolicy)
				}
				// The lease gate must still refuse to run it as a pool image.
				executor := fixture.manager.executors["codex"].(*poolExecutor)
				lease, errBegin := executor.begin(ctx, fixture.auth, cliproxyexecutor.Request{Model: "gpt-image-2", Payload: opts.OriginalRequest}, opts, false, true)
				if !errors.Is(errBegin, ErrPoolGuard) || lease != nil {
					t.Fatalf("unsigned images request acquired a lease: lease=%v err=%v", lease, errBegin)
				}
				return
			}
			if scenario == "n-not-one" {
				if !errors.Is(errPolicy, ErrPoolGuard) || policy != nil {
					t.Fatalf("n=2 must be rejected before admission: policy=%v err=%v", policy, errPolicy)
				}
				return
			}
			if errPolicy != nil {
				t.Fatalf("policy verification failed: %v", errPolicy)
			}
			if len(ids) != 1 || ids[0] != fixture.authID {
				t.Fatalf("account order resolved to %v", ids)
			}
			ctx = withPG03ImagesPolicy(ctx, policy)
			executor := fixture.manager.executors["codex"].(*poolExecutor)
			transport := executor.ProviderExecutor.(*imagesProbeExecutor)

			lease, errBegin := executor.begin(ctx, fixture.auth, cliproxyexecutor.Request{Model: "gpt-image-2", Payload: opts.OriginalRequest}, opts, false, true)
			if scenario == "no-capability" || scenario == "base-model-mismatch" {
				if !errors.Is(errBegin, ErrPoolGuard) || lease != nil {
					t.Fatalf("%s must not admit: lease=%v err=%v", scenario, lease, errBegin)
				}
				return
			}
			if errBegin != nil {
				t.Fatalf("admission failed: %v", errBegin)
			}
			if scenario == "n-not-one" {
				// The transport shape gate rejects a multi-image request before
				// admission, so begin must already have failed above.
				t.Fatal("n=2 must not be admitted")
			}
			upstream := `{"model":"gpt-5.4-mini","tools":[{"type":"image_generation","action":"generate","model":"gpt-image-2"}]}`
			req, errReq := http.NewRequest(http.MethodPost, "https://chatgpt.com/backend-api/codex/responses", strings.NewReader(upstream))
			if errReq != nil {
				t.Fatal(errReq)
			}
			req.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(strings.NewReader(upstream)), nil }
			if err := cliproxyexecutor.BeforeUpstreamDispatch(lease.ctx, req); err != nil {
				t.Fatalf("dispatch fence rejected a valid images request: %v", err)
			}
			if err := cliproxyexecutor.MarkUpstreamDispatchStarted(lease.ctx); err != nil {
				t.Fatalf("dispatch observer failed: %v", err)
			}

			var persistErr error
			switch scenario {
			case "result-storage-failure":
				if err := os.RemoveAll(fixture.resultsDir); err != nil {
					t.Fatal(err)
				}
				persistErr = lease.PersistImagesResult(fixture.payload, 1)
			case "no-image-output":
				persistErr = lease.PersistImagesResult([]byte(`{"created":1,"data":[]}`), 1)
			default:
				persistErr = lease.PersistImagesResult(fixture.payload, 1)
			}

			record, errQuery := fixture.manager.QueryImagesExecution("images-request", "images-attempt")
			if errQuery != nil {
				t.Fatalf("durable query failed: %v", errQuery)
			}
			if !record.Found || record.State != "STARTED" {
				t.Fatalf("durable record missing: %#v", record)
			}
			switch scenario {
			case "success":
				if persistErr != nil {
					t.Fatalf("persist failed: %v", persistErr)
				}
				if record.ResultState != "COMPLETED" || record.BillableCount != 1 || record.ResultSHA256 == "" || record.ResultRef == "" {
					t.Fatalf("unexpected durable record: %#v", record)
				}
				stored, meta, errLoad := fixture.manager.LoadImagesResult("images-request", "images-attempt")
				if errLoad != nil || !equalBytes(stored, fixture.payload) || meta.BillableImageCount != 1 {
					t.Fatalf("stored payload mismatch: err=%v meta=%#v", errLoad, meta)
				}
				if err := lease.PersistImagesResult(fixture.payload, 1); !errors.Is(err, ErrPoolGuard) {
					t.Fatalf("duplicate result publication allowed: %v", err)
				}
				again, errAgain := fixture.manager.QueryImagesExecution("images-request", "images-attempt")
				if errAgain != nil || again.ResultSHA256 != record.ResultSHA256 {
					t.Fatalf("duplicate publication changed the record: %#v", again)
				}
			case "result-storage-failure":
				if persistErr == nil {
					t.Fatal("success was reported after the result store disappeared")
				}
				if record.ResultState == "COMPLETED" {
					t.Fatalf("success published without a durable result: %#v", record)
				}
			case "no-image-output":
				if persistErr == nil {
					t.Fatal("zero images must not report success")
				}
				if record.ResultState != "FAILED" || record.BillableCount != 0 || record.EndReason != "no_image_output" {
					t.Fatalf("zero-image record wrong: %#v", record)
				}
			}
			if transport.calls.Load() != 0 {
				t.Fatal("synthetic transport must not be reached by the lease test")
			}
		})
	}
}

// TestPG03ImagesExecutorPersistsBeforeSuccess proves the production wiring: the
// pool executor persists the provider payload and only then returns it, and a
// provider error finalizes the attempt as a non-success receipt.
func TestPG03ImagesExecutorPersistsBeforeSuccess(t *testing.T) {
	t.Setenv("CLEARAPI_PG02_RESPONSES_SSE", "")
	t.Setenv("CLEARAPI_PG02_HTTP_NON_STREAM", "")
	t.Setenv("CLEARAPI_PG03_IMAGES", "true")
	t.Setenv("CLEARAPI_PG03_IMAGES_POLICY_KEY", "synthetic-images-policy-key-012345678901234567890123")
	t.Setenv("CLEARAPI_PG02_PROCESS_EPOCH", "00112233445566778899aabbccddeeff")

	for _, scenario := range []string{"success", "provider-error"} {
		t.Run(scenario, func(t *testing.T) {
			fixture := newImagesFixture(t, scenario)
			payload := []byte(`{"model":"gpt-image-2","prompt":"a cat","n":1}`)
			opts := cliproxyexecutor.Options{OriginalRequest: payload, Headers: http.Header{}, Metadata: map[string]any{cliproxyexecutor.RequestPathMetadataKey: "/v1/images/generations"}}
			opts.Headers.Set(pg03ImagesRequestHeader, "images-request")
			opts.Headers.Set(pg03ImagesAttemptHeader, "images-attempt")
			signImagesPolicy(t, opts.Headers, payload, scenario)
			ctx := context.WithValue(context.Background(), poolAttemptContextKey{}, &atomicPoolAttempt{})
			policy, _, errPolicy := fixture.manager.verifyPG03ImagesPolicy(ctx, []string{"codex"}, opts)
			if errPolicy != nil {
				t.Fatalf("policy verification failed: %v", errPolicy)
			}
			ctx = withPG03ImagesPolicy(ctx, policy)
			executor := fixture.manager.executors["codex"].(*poolExecutor)
			probe := executor.ProviderExecutor.(*imagesProbeExecutor)
			probe.failure = scenario == "provider-error"

			response, errExecute := executor.Execute(ctx, fixture.auth, cliproxyexecutor.Request{Model: "gpt-image-2", Payload: payload}, opts)
			record, errQuery := fixture.manager.QueryImagesExecution("images-request", "images-attempt")
			if errQuery != nil {
				t.Fatalf("durable query failed: %v", errQuery)
			}
			switch scenario {
			case "success":
				if errExecute != nil {
					t.Fatalf("execute failed: %v", errExecute)
				}
				if len(response.Payload) == 0 || record.ResultState != "COMPLETED" || record.BillableCount != 1 {
					t.Fatalf("success was not persisted with the payload: record=%#v", record)
				}
			case "provider-error":
				if errExecute == nil {
					t.Fatal("provider error was hidden")
				}
				if record.ResultState == "COMPLETED" || record.BillableCount != 0 {
					t.Fatalf("failed attempt published a completed image result: %#v", record)
				}
			}
			if probe.calls.Load() != 1 {
				t.Fatalf("provider transport calls = %d, want 1", probe.calls.Load())
			}
		})
	}
}

// TestPG03ImagesQueryDistinguishesMissingFromBroken proves the zero-dispatch
// proof cannot be forged by a storage fault: an absent attempt answers
// found=false, while an unusable receipt store still returns an error. Letting
// the two collapse would make the Gateway treat a broken store as proof that
// nothing was sent, which is exactly the condition that authorizes a second
// dispatch against another source.
func TestPG03ImagesQueryDistinguishesMissingFromBroken(t *testing.T) {
	t.Setenv("CLEARAPI_PG03_IMAGES", "true")
	t.Setenv("CLEARAPI_PG03_IMAGES_POLICY_KEY", "synthetic-images-policy-key-012345678901234567890123")
	t.Setenv("CLEARAPI_PG02_PROCESS_EPOCH", "00112233445566778899aabbccddeeff")

	fixture := newImagesFixture(t, "success")

	record, errMissing := fixture.manager.QueryImagesExecution("missing-request", "missing-attempt")
	if errMissing != nil {
		t.Fatalf("an absent attempt must answer found=false, not an error: %v", errMissing)
	}
	if record.Found {
		t.Fatalf("an absent attempt reported found=true: %#v", record)
	}
	if record.RequestID != "missing-request" || record.AttemptID != "missing-attempt" {
		t.Fatalf("the answer must echo the queried identity: %#v", record)
	}

	// A faulted receipt writer is a store failure, never a zero-dispatch proof.
	guard := fixture.manager.poolGuard
	if guard == nil || guard.receipts == nil {
		t.Fatal("fixture has no receipt writer")
	}
	guard.receipts.faulted.Store(true)
	if _, errBroken := fixture.manager.QueryImagesExecution("missing-request", "missing-attempt"); errBroken == nil {
		t.Fatal("a faulted receipt store must not answer found=false")
	}
}

// TestPG03ImagesRestartRecovery proves that a fresh process (new Manager, new
// guards, same receipt/result directories) answers the durable question for an
// existing attempt instead of dispatching again.
func TestPG03ImagesRestartRecovery(t *testing.T) {
	t.Setenv("CLEARAPI_PG02_RESPONSES_SSE", "")
	t.Setenv("CLEARAPI_PG02_HTTP_NON_STREAM", "")
	t.Setenv("CLEARAPI_PG03_IMAGES", "true")
	t.Setenv("CLEARAPI_PG03_IMAGES_POLICY_KEY", "synthetic-images-policy-key-012345678901234567890123")
	t.Setenv("CLEARAPI_PG02_PROCESS_EPOCH", "00112233445566778899aabbccddeeff")

	fixture := newImagesFixture(t, "success")
	payload := []byte(`{"model":"gpt-image-2","prompt":"a cat","n":1}`)
	opts := cliproxyexecutor.Options{OriginalRequest: payload, Headers: http.Header{}, Metadata: map[string]any{cliproxyexecutor.RequestPathMetadataKey: "/v1/images/generations"}}
	opts.Headers.Set(pg03ImagesRequestHeader, "images-request")
	opts.Headers.Set(pg03ImagesAttemptHeader, "images-attempt")
	signImagesPolicy(t, opts.Headers, payload, "success")
	ctx := context.WithValue(context.Background(), poolAttemptContextKey{}, &atomicPoolAttempt{})
	policy, _, errPolicy := fixture.manager.verifyPG03ImagesPolicy(ctx, []string{"codex"}, opts)
	if errPolicy != nil {
		t.Fatalf("policy verification failed: %v", errPolicy)
	}
	ctx = withPG03ImagesPolicy(ctx, policy)
	executor := fixture.manager.executors["codex"].(*poolExecutor)
	lease, errBegin := executor.begin(ctx, fixture.auth, cliproxyexecutor.Request{Model: "gpt-image-2", Payload: payload}, opts, false, true)
	if errBegin != nil {
		t.Fatalf("admission failed: %v", errBegin)
	}
	upstream := `{"model":"gpt-5.4-mini","tools":[{"type":"image_generation","action":"generate","model":"gpt-image-2"}]}`
	req, errReq := http.NewRequest(http.MethodPost, "https://chatgpt.com/backend-api/codex/responses", strings.NewReader(upstream))
	if errReq != nil {
		t.Fatal(errReq)
	}
	req.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(strings.NewReader(upstream)), nil }
	if err := cliproxyexecutor.BeforeUpstreamDispatch(lease.ctx, req); err != nil {
		t.Fatalf("dispatch fence rejected the request: %v", err)
	}
	if err := cliproxyexecutor.MarkUpstreamDispatchStarted(lease.ctx); err != nil {
		t.Fatalf("dispatch observer failed: %v", err)
	}
	if err := lease.PersistImagesResult(fixture.payload, 1); err != nil {
		t.Fatalf("persist failed: %v", err)
	}
	before, errQuery := fixture.manager.QueryImagesExecution("images-request", "images-attempt")
	if errQuery != nil || before.ResultState != "COMPLETED" {
		t.Fatalf("pre-restart record wrong: %#v err=%v", before, errQuery)
	}
	lease.End("completed")

	// A new manager instance reads the same directories. Nothing in memory is
	// shared, so this is the restart criterion that matters for recovery.
	restarted := NewManager(nil, nil, nil)
	restarted.SetConfig(fixture.manager.runtimeConfig.Load().(*internalconfig.Config))
	after, errAfter := restarted.QueryImagesExecution("images-request", "images-attempt")
	if errAfter != nil {
		t.Fatalf("post-restart query failed: %v", errAfter)
	}
	if !after.Found || after.ResultState != "COMPLETED" || after.ResultSHA256 != before.ResultSHA256 || after.BillableCount != 1 {
		t.Fatalf("restart did not recover the original attempt: before=%#v after=%#v", before, after)
	}
	stored, meta, errLoad := restarted.LoadImagesResult("images-request", "images-attempt")
	if errLoad != nil || !equalBytes(stored, fixture.payload) || meta.ResultSHA256 != before.ResultSHA256 {
		t.Fatalf("restart could not recover the persisted payload: err=%v", errLoad)
	}
	// A different attempt for the same request has no record: recovery must
	// report "not found" rather than inventing a new generation. This is also
	// the trusted zero-dispatch proof the Gateway needs before it may hand a
	// request over to another source, so it must be a successful answer with
	// Found=false, NOT a store error.
	missing, errMissing := restarted.QueryImagesExecution("images-request", "images-attempt-2")
	if errMissing != nil {
		t.Fatalf("a missing attempt must answer found=false, not an error: %v", errMissing)
	}
	if missing.Found || missing.State != "" || missing.ResultState != "" {
		t.Fatalf("missing attempt must report found=false with no terminal state: %#v", missing)
	}
}

// imagesProbeExecutor is a synthetic provider transport for the images
// contract. It never opens a network connection and records dispatch attempts.
type imagesProbeExecutor struct {
	calls        atomic.Int32
	failure      bool
	payload      []byte
	upstreamBody string
}

func (*imagesProbeExecutor) Identifier() string        { return "codex" }
func (*imagesProbeExecutor) PoolDispatchFencing() bool { return true }

func (e *imagesProbeExecutor) Execute(ctx context.Context, _ *Auth, _ cliproxyexecutor.Request, _ cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
	if err := cliproxyexecutor.BeforeUpstreamDispatch(ctx); err != nil {
		return cliproxyexecutor.Response{}, err
	}
	e.calls.Add(1)
	if err := cliproxyexecutor.MarkUpstreamDispatchStarted(ctx); err != nil {
		return cliproxyexecutor.Response{}, err
	}
	if e.failure {
		return cliproxyexecutor.Response{}, &Error{HTTPStatus: http.StatusBadGateway, Message: "synthetic image provider failure"}
	}
	payload := e.payload
	if payload == nil {
		payload = []byte(`{"created":1,"data":[{"b64_json":"c3ludGhldGlj"}]}`)
	}
	return cliproxyexecutor.Response{Payload: payload}, nil
}

func (*imagesProbeExecutor) ExecuteStream(context.Context, *Auth, cliproxyexecutor.Request, cliproxyexecutor.Options) (*cliproxyexecutor.StreamResult, error) {
	return nil, ErrPoolGuard
}

func (e *imagesProbeExecutor) CountTokens(ctx context.Context, auth *Auth, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
	return e.Execute(ctx, auth, req, opts)
}

func (*imagesProbeExecutor) Refresh(_ context.Context, auth *Auth) (*Auth, error) {
	return auth.Clone(), nil
}

func (*imagesProbeExecutor) HttpRequest(context.Context, *Auth, *http.Request) (*http.Response, error) {
	return nil, ErrPoolGuard
}

type imagesFixture struct {
	manager    *Manager
	auth       *Auth
	authID     string
	payload    []byte
	resultsDir string
}

func newImagesFixture(t *testing.T, scenario string) imagesFixture {
	t.Helper()
	root := t.TempDir()
	dir := filepath.Join(root, "auths")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	results := filepath.Join(root, "results")
	if err := os.Mkdir(results, 0700); err != nil {
		t.Fatal(err)
	}
	receipts := filepath.Join(root, "receipts")
	if err := os.Mkdir(receipts, 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv(receiptDirEnv, receipts)
	t.Setenv(imagesResultDirEnv, results)
	file := filepath.Join(root, "grants.json")
	checkpoint := filepath.Join(root, "checkpoint.jsonl")
	t.Setenv("CLEARAPI_POOL_ROLE", "service")
	t.Setenv("CLEARAPI_POOL_ADMISSION_FILE", file)
	t.Setenv("CLEARAPI_POOL_EXECUTOR_ID", "synthetic-images-executor")
	t.Setenv("CLEARAPI_POOL_CHECKPOINT_FILE", checkpoint)
	if err := ProvisionPoolCheckpoint(checkpoint, "synthetic-images-executor"); err != nil {
		t.Fatal(err)
	}
	manager := NewManager(nil, nil, nil)
	manager.SetConfig(&internalconfig.Config{AuthDir: dir})
	auth := &Auth{ID: "images-account", Provider: "codex", Status: StatusActive, Attributes: map[string]string{AttributeAuthKind: AuthKindOAuth}, Metadata: map[string]any{"access_token": "synthetic", "account_id": "synthetic", "email": "images@synthetic.invalid"}}
	auth.FileName = "images-account.json"
	models := []string{"gpt-image-2", "gpt-5.4-mini"}
	if scenario == "base-model-mismatch" {
		models = []string{"gpt-image-2"}
	}
	record := PoolGrantFile{GuardVersion: PoolGuardVersion, ExecutorID: "synthetic-images-executor", Revision: 1, Grants: []PoolGrant{{
		AuthID: auth.ID, Provider: auth.Provider, CredentialDigest: PoolCredentialDigest(auth), Models: models,
		Capabilities: []string{"text_chat", "exact_usage", ImagePoolCapability}, Enabled: true, MaxConcurrency: 1,
		ExpiresAt: nowUnix() + 600, SourceEvidence: []string{"synthetic"}, TestEvidence: []string{"synthetic"},
	}}}
	writePoolGrant(t, file, record)
	transport := &imagesProbeExecutor{}
	manager.RegisterExecutor(transport)
	if _, err := manager.Register(context.Background(), auth); err != nil {
		t.Fatal(err)
	}
	if err := manager.PromotePoolIdentities(context.Background(), PoolPromotion{ExpectedRevision: record.Revision, Identities: []PoolIdentityExpectation{{AuthID: auth.ID, Provider: auth.Provider, CredentialDigest: PoolCredentialDigest(auth)}}}); err != nil {
		t.Fatal(err)
	}
	for _, model := range models {
		if err := grantPoolModelCapability(t, manager, auth, model); err != nil {
			t.Fatal(err)
		}
	}
	registry.GetGlobalRegistry().RegisterClient(auth.ID, auth.Provider, []*registry.ModelInfo{{ID: "gpt-image-2"}, {ID: "gpt-5.4-mini"}})
	t.Cleanup(func() { registry.GetGlobalRegistry().UnregisterClient(auth.ID) })
	registered, ok := manager.GetByID(auth.ID)
	if !ok {
		t.Fatal("registered account missing")
	}
	if scenario == "no-capability" {
		if err := revokePoolModelCapability(t, manager, registered, "gpt-image-2"); err != nil {
			t.Fatal(err)
		}
	}
	return imagesFixture{manager: manager, auth: registered, authID: auth.ID, payload: []byte(`{"created":1,"data":[{"b64_json":"c3ludGhldGlj"}]}`), resultsDir: results}
}

func signImagesPolicy(t *testing.T, headers http.Header, payload []byte, scenario string) {
	t.Helper()
	policy := pg03ImagesPolicySnapshot{
		Schema: 2, Operation: pg03ImagesOperation, PolicyID: 12, PoolID: "synthetic-pool",
		ModelName: "gpt-image-2", BaseModel: "gpt-5.4-mini",
		AccountOrder: []string{"images-account.json"}, MaxFallbackCount: 0,
		RequestID: "images-request", AttemptID: "images-attempt",
		Method: http.MethodPost, Path: pg03ImagesPath,
		BodyDigest: sha256Hex(payload),
		IssuedAt:   nowUnix(),
	}
	if scenario == "base-model-mismatch" {
		policy.BaseModel = "gpt-unlisted-base"
		policy.BodyDigest = sha256Hex(payload)
	}
	encoded, err := jsonMarshal(policy)
	if err != nil {
		t.Fatal(err)
	}
	headers.Set(pg03ImagesPolicyHeader, base64RawURL(encoded))
	headers.Set(pg03ImagesSignatureHeader, hmacHex(encoded))
}

func sha256Hex(payload []byte) string {
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:])
}

func jsonMarshal(value any) ([]byte, error) { return json.Marshal(value) }

func base64RawURL(payload []byte) string { return base64.RawURLEncoding.EncodeToString(payload) }

func hmacHex(payload []byte) string {
	mac := hmac.New(sha256.New, []byte(os.Getenv("CLEARAPI_PG03_IMAGES_POLICY_KEY")))
	mac.Write([]byte(pg03ImagesSignatureDomain))
	mac.Write(payload)
	return hex.EncodeToString(mac.Sum(nil))
}

func nowUnix() int64 { return time.Now().Unix() }
