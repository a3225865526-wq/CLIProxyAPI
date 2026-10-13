package auth

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/gin-gonic/gin"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	internalconfig "github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
)

type pg03StreamProbe struct {
	poolProbeExecutor
	rejects      int
	mode         string
	order        []string
	dispatches   map[string]int
	dir          string
	firstReceipt string
}

func poolReceiptIDForTest(request, attempt, account string) string {
	digest := sha256.Sum256([]byte(request + "\n" + attempt + "\n" + account))
	return hex.EncodeToString(digest[:])
}

func (e *pg03StreamProbe) ExecuteStream(ctx context.Context, auth *Auth, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) (*cliproxyexecutor.StreamResult, error) {
	e.order = append(e.order, auth.ID)
	if len(e.order) <= e.rejects {
		err := cliproxyexecutor.LocalAccountUnavailable(ctx)
		var proof *poolSSEZeroDispatchError
		if errors.As(err, &proof) {
			if e.firstReceipt == "" {
				e.firstReceipt = proof.final.ReceiptID
			}
			if e.mode == "invalid" || (e.mode == "ancestor-invalid" && len(e.order) == 2) {
				if errWrite := os.WriteFile(filepath.Join(e.dir, e.firstReceipt+".jsonl"), []byte("tampered\n"), 0600); errWrite != nil {
					return nil, errWrite
				}
			}
		}
		if e.mode == "dispatch" && len(e.order) == e.rejects {
			cliproxyexecutor.MarkUpstreamAttempt(ctx)
		}
		return nil, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://synthetic.invalid/responses", strings.NewReader(string(opts.OriginalRequest)))
	if err != nil {
		return nil, err
	}
	if err := cliproxyexecutor.BeforeUpstreamDispatch(ctx, request); err != nil {
		return nil, err
	}
	if e.mode == "unknown" || e.mode == "fence-uncertain" {
		return nil, ErrPoolGuard
	}
	if err := cliproxyexecutor.MarkUpstreamDispatchStarted(ctx); err != nil {
		return nil, err
	}
	cliproxyexecutor.MarkUpstreamAttempt(ctx)
	e.dispatches[auth.ID]++
	if err := cliproxyexecutor.BeforeUpstreamDispatch(ctx, request); err == nil {
		return nil, errors.New("second dispatch was authorized")
	}
	if e.mode == "started" {
		return nil, errors.New("synthetic failure after STARTED")
	}
	terminal := []byte(`{"type":"response.completed","response":{"id":"pg03-synthetic","status":"completed","usage":{"input_tokens":1,"output_tokens":1,"total_tokens":2}}}`)
	if err := cliproxyexecutor.PersistResponsesSSEEvent(ctx, terminal); err != nil {
		return nil, err
	}
	chunks := make(chan cliproxyexecutor.StreamChunk, 1)
	chunks <- cliproxyexecutor.StreamChunk{Payload: terminal}
	close(chunks)
	return &cliproxyexecutor.StreamResult{Chunks: chunks}, nil
}

func pg03ChainFixture(t *testing.T, probe *pg03StreamProbe) *Manager {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("durable receipt attestation requires Linux")
	}
	root := t.TempDir()
	for _, name := range []string{"auths", "receipts"} {
		if err := os.Mkdir(filepath.Join(root, name), 0700); err != nil {
			t.Fatal(err)
		}
	}
	probe.dir = filepath.Join(root, "receipts")
	probe.dispatches = make(map[string]int)
	file := filepath.Join(root, "grants.json")
	checkpoint := filepath.Join(root, "checkpoint.jsonl")
	t.Setenv(receiptDirEnv, probe.dir)
	t.Setenv("CLEARAPI_POOL_ROLE", "service")
	t.Setenv("CLEARAPI_POOL_ADMISSION_FILE", file)
	t.Setenv("CLEARAPI_POOL_EXECUTOR_ID", "pg03-synthetic")
	t.Setenv("CLEARAPI_POOL_CHECKPOINT_FILE", checkpoint)
	t.Setenv("CLEARAPI_PG02_RESPONSES_SSE", "true")
	t.Setenv("CLEARAPI_PG02_HTTP_NON_STREAM", "")
	t.Setenv("CLEARAPI_PG02_PROCESS_EPOCH", "00112233445566778899aabbccddeeff")
	t.Setenv("CLEARAPI_PG02_GATEWAY_PROOF_KEY", "synthetic-pg03-proof-key-for-unit-tests-only")
	if err := ProvisionPoolCheckpoint(checkpoint, "pg03-synthetic"); err != nil {
		t.Fatal(err)
	}
	m := NewManager(nil, &FillFirstSelector{}, nil)
	m.SetConfig(&internalconfig.Config{AuthDir: filepath.Join(root, "auths")})
	m.RegisterExecutor(probe)
	record := PoolGrantFile{GuardVersion: PoolGuardVersion, ExecutorID: "pg03-synthetic", Revision: 1}
	var accounts []*Auth
	var identities []PoolIdentityExpectation
	for i := 0; i < 5; i++ {
		id := fmt.Sprintf("pg03-%c", 'A'+i)
		auth := &Auth{ID: id, Provider: "codex", Status: StatusActive, Attributes: map[string]string{AttributeAuthKind: AuthKindOAuth}, Metadata: map[string]any{"access_token": "synthetic-" + id, "account_id": id, "email": id + "@synthetic.invalid"}}
		accounts = append(accounts, auth)
		identities = append(identities, PoolIdentityExpectation{AuthID: id, Provider: "codex", CredentialDigest: PoolCredentialDigest(auth)})
		record.Grants = append(record.Grants, PoolGrant{AuthID: id, Provider: "codex", CredentialDigest: PoolCredentialDigest(auth), Models: []string{"synthetic-native"}, Capabilities: []string{"text_chat", "stream_text", "exact_usage"}, Enabled: true, MaxConcurrency: 1, ExpiresAt: time.Now().Add(10 * time.Minute).Unix(), SourceEvidence: []string{"synthetic-source"}, TestEvidence: []string{"synthetic-test"}})
	}
	writePoolGrant(t, file, record)
	for _, auth := range accounts {
		if _, err := m.Register(context.Background(), auth); err != nil {
			t.Fatal(err)
		}
	}
	if err := m.PromotePoolIdentities(context.Background(), PoolPromotion{ExpectedRevision: 1, Identities: identities}); err != nil {
		t.Fatal(err)
	}
	for _, auth := range accounts {
		if err := grantPoolModelCapability(t, m, auth, "synthetic-native"); err != nil {
			t.Fatal(err)
		}
		registry.GetGlobalRegistry().RegisterClient(auth.ID, "codex", []*registry.ModelInfo{{ID: "synthetic-native"}})
		id := auth.ID
		t.Cleanup(func() { registry.GetGlobalRegistry().UnregisterClient(id) })
	}
	// The PG03 bound is independent of legacy credential retry settings.
	m.SetRetryConfig(3, 0, 1)
	return m
}

func TestPG03SSEFallbackChain(t *testing.T) {
	for _, test := range []struct {
		name                        string
		rejects, attempts, dispatch int
		success                     bool
	}{
		{"success", 2, 3, 1, true},
		{"four-rejections", 5, 4, 0, false},
		{"fourth-success", 3, 4, 1, true},
		{"started", 0, 1, 1, false},
		{"started-after-two", 2, 3, 1, false},
		{"unknown", 0, 1, 0, false},
		{"unknown-after-two", 2, 3, 0, false},
		{"fence-uncertain", 0, 1, 0, false},
		{"fence-uncertain-after-two", 2, 3, 0, false},
		{"dispatch", 1, 1, 0, false},
		{"dispatch-after-two", 3, 3, 0, false},
		{"invalid", 1, 1, 0, false},
		{"ancestor-invalid", 2, 2, 0, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			probe := &pg03StreamProbe{rejects: test.rejects, mode: strings.TrimSuffix(test.name, "-after-two")}
			m := pg03ChainFixture(t, probe)
			ctx, opts := capacityOptions("pg03-chain")
			opts.OriginalRequest = []byte(`{"model":"synthetic-native","stream":true}`)
			installPG03TestPolicy(t, &opts)
			result, err := m.ExecuteStream(ctx, []string{"codex"}, cliproxyexecutor.Request{Model: "synthetic-native", Payload: opts.OriginalRequest}, opts)
			if (err == nil) != test.success {
				t.Fatalf("success=%v, err=%v", test.success, err)
			}
			if result != nil {
				for chunk := range result.Chunks {
					if chunk.Err != nil {
						t.Fatal(chunk.Err)
					}
				}
			}
			if test.name == "invalid" || test.name == "ancestor-invalid" {
				if isPoolSSEZeroDispatchError(err) {
					t.Fatal("invalid receipt escaped as reusable fallback proof")
				}
			}
			var want []string
			for i := 0; i < test.attempts; i++ {
				want = append(want, fmt.Sprintf("pg03-%c", 'A'+i))
			}
			if !reflect.DeepEqual(probe.order, want) {
				t.Fatalf("order=%v, want=%v", probe.order, want)
			}
			total := 0
			for _, count := range probe.dispatches {
				total += count
			}
			if total != test.dispatch {
				t.Fatalf("dispatches=%v, total=%d, want=%d", probe.dispatches, total, test.dispatch)
			}
			if test.success && probe.dispatches[want[len(want)-1]] != 1 {
				t.Fatal("wrong account dispatched")
			}
			if probe.dispatches["pg03-E"] != 0 {
				t.Fatal("fifth account dispatched")
			}
			if test.name == "success" || test.name == "four-rejections" || test.name == "fourth-success" {
				previous := ""
				for _, id := range want {
					digest := poolReceiptIDForTest("pg03-chain", "pg03-chain-attempt", id)
					data, err := os.ReadFile(filepath.Join(probe.dir, digest+".jsonl"))
					if err != nil {
						t.Fatal(err)
					}
					lines := strings.Split(strings.TrimSpace(string(data)), "\n")
					var final receiptEvent
					if err := json.Unmarshal([]byte(lines[len(lines)-1]), &final); err != nil {
						t.Fatal(err)
					}
					state := "NOT_STARTED"
					if probe.dispatches[id] == 1 {
						state = "STARTED"
					}
					if final.State != state || final.Event != "FINAL" || final.PreviousReceiptID != previous {
						t.Fatalf("invalid final: %+v", final)
					}
					if state == "STARTED" && final.SSE.ResultState != "COMPLETED" {
						t.Fatal("missing successful FINAL")
					}
					previous = final.ReceiptID
				}
			}
		})
	}
}

func installPG03TestPolicy(t *testing.T, opts *cliproxyexecutor.Options) {
	t.Helper()
	order := []string{"pg03-A", "pg03-B", "pg03-C", "pg03-D"}
	policy := pg03PolicySnapshot{PolicyID: 1, PoolID: "synthetic", ModelName: "synthetic-native", AccountOrder: order, MaxFallbackCount: 3, RequestID: opts.Headers.Get("X-ClearAPI-PG02-Request"), Method: http.MethodPost, Path: "/v1/responses", IssuedAt: time.Now().Unix()}
	digest := sha256.Sum256(opts.OriginalRequest)
	policy.BodyDigest = hex.EncodeToString(digest[:])
	payload, err := json.Marshal(policy)
	if err != nil {
		t.Fatal(err)
	}
	key := "synthetic-pg03-policy-key-012345678901234567890123456789"
	t.Setenv("CLEARAPI_PG03_POLICY_KEY", key)
	mac := hmac.New(sha256.New, []byte(key))
	mac.Write([]byte("clearapi-pg03-policy-v1\n"))
	mac.Write(payload)
	opts.Headers.Set(pg03PolicyHeader, base64.RawURLEncoding.EncodeToString(payload))
	opts.Headers.Set(pg03SignatureHeader, hex.EncodeToString(mac.Sum(nil)))
	opts.Headers.Set(pg03RequestHeader, policy.RequestID)
	proof := hmac.New(sha256.New, []byte(os.Getenv("CLEARAPI_PG02_GATEWAY_PROOF_KEY")))
	proof.Write([]byte(policy.RequestID + "\n" + policy.RequestID + "-attempt\nPOST\n/v1/responses\n"))
	proof.Write(opts.OriginalRequest)
	opts.Headers.Set("X-ClearAPI-PG02-Gateway-Proof", hex.EncodeToString(proof.Sum(nil)))
}

func TestPG03SnapshotBoundary(t *testing.T) {
	for _, name := range []string{"absent", "valid", "reverse", "limit-zero", "limit-one", "signature", "request-binding", "body-binding", "path-binding", "malformed", "missing-mapping", "duplicate-ref", "ambiguous-mapping", "limit-four", "expired", "duplicate-header", "replay"} {
		t.Run(name, func(t *testing.T) {
			probe := &pg03StreamProbe{rejects: 2}
			m := pg03ChainFixture(t, probe)
			m.SetRetryConfig(3, 0, 5)
			ctx, opts := capacityOptions("boundary-" + name)
			if name != "absent" {
				opts.OriginalRequest = []byte(`{"model":"synthetic-native","stream":true}`)
				installPG03TestPolicy(t, &opts)
			}
			var policy pg03PolicySnapshot
			if name != "absent" {
				payload, err := base64.RawURLEncoding.DecodeString(opts.Headers.Get(pg03PolicyHeader))
				if err != nil {
					t.Fatal(err)
				}
				if err := json.Unmarshal(payload, &policy); err != nil {
					t.Fatal(err)
				}
			}
			switch name {
			case "reverse":
				policy.AccountOrder = []string{"pg03-D", "pg03-C", "pg03-B", "pg03-A"}
				probe.rejects = 0
			case "limit-zero":
				policy.MaxFallbackCount = 0
			case "limit-one":
				policy.MaxFallbackCount = 1
			case "missing-mapping":
				policy.AccountOrder[3] = "missing"
			case "duplicate-ref":
				policy.AccountOrder[3] = "pg03-A"
			case "ambiguous-mapping":
				m.mu.Lock()
				m.auths["pg03-B"].FileName = "pg03-A"
				m.mu.Unlock()
			case "limit-four":
				policy.MaxFallbackCount = 4
			case "expired":
				policy.IssuedAt = time.Now().Add(-10 * time.Minute).Unix()
			}
			if name != "absent" {
				payload, err := json.Marshal(policy)
				if err != nil {
					t.Fatal(err)
				}
				mac := hmac.New(sha256.New, []byte(os.Getenv("CLEARAPI_PG03_POLICY_KEY")))
				mac.Write([]byte("clearapi-pg03-policy-v1\n"))
				mac.Write(payload)
				opts.Headers.Set(pg03PolicyHeader, base64.RawURLEncoding.EncodeToString(payload))
				opts.Headers.Set(pg03SignatureHeader, hex.EncodeToString(mac.Sum(nil)))
			}
			switch name {
			case "signature":
				opts.Headers.Set(pg03SignatureHeader, strings.Repeat("0", 64))
			case "request-binding":
				opts.Headers.Set(pg03RequestHeader, "wrong-request")
			case "body-binding":
				opts.OriginalRequest = append(opts.OriginalRequest, ' ')
			case "path-binding":
				opts.Metadata[cliproxyexecutor.RequestPathMetadataKey] = "/v1/chat/completions"
			case "malformed":
				opts.Headers.Set(pg03PolicyHeader, "not-json")
			case "duplicate-header":
				opts.Headers.Add(pg03SignatureHeader, opts.Headers.Get(pg03SignatureHeader))
			}
			result, err := m.ExecuteStream(ctx, []string{"codex"}, cliproxyexecutor.Request{Model: "synthetic-native", Payload: opts.OriginalRequest}, opts)
			if result != nil {
				for chunk := range result.Chunks {
					if chunk.Err != nil {
						t.Fatal(chunk.Err)
					}
				}
			}
			want := []string(nil)
			switch name {
			case "valid", "replay":
				want = []string{"pg03-A", "pg03-B", "pg03-C"}
			case "reverse":
				want = []string{"pg03-D"}
			case "absent", "limit-one":
				want = []string{"pg03-A", "pg03-B"}
			case "limit-zero":
				want = []string{"pg03-A"}
			}
			if !reflect.DeepEqual(probe.order, want) {
				t.Fatalf("order=%v want=%v err=%v", probe.order, want, err)
			}
			success := name == "valid" || name == "reverse" || name == "replay"
			if (err == nil) != success {
				t.Fatalf("success=%v err=%v", success, err)
			}
			if name == "valid" && (probe.dispatches["pg03-A"] != 0 || probe.dispatches["pg03-B"] != 0 || probe.dispatches["pg03-C"] != 1) {
				t.Fatalf("dispatch=%v", probe.dispatches)
			}
			if name == "replay" {
				// A new request context cannot reuse an already durable BEGIN.
				ctx, _ = capacityOptions("boundary-replay")
				before := len(probe.order)
				_, err = m.ExecuteStream(ctx, []string{"codex"}, cliproxyexecutor.Request{Model: "synthetic-native", Payload: opts.OriginalRequest}, opts)
				if err == nil || len(probe.order) != before || probe.dispatches["pg03-C"] != 1 {
					t.Fatalf("replay redispatched: err=%v order=%v", err, probe.order)
				}
			}
		})
	}
}

// Optional cross-repository wire evidence is emitted by Gateway's real CRUD
// and signing functions, not re-signed or translated by this consumer.
func TestPG03GatewayWireIntegration(t *testing.T) {
	directory := os.Getenv("PG03_WIRE_EVIDENCE_DIR")
	if directory == "" {
		t.Skip("requires freshly emitted Gateway wire evidence")
	}
	for _, name := range []string{"gateway-ABCD", "gateway-old-ABCD", "gateway-DCBA"} {
		t.Run(name, func(t *testing.T) {
			probe := &pg03StreamProbe{rejects: 2}
			if name == "gateway-DCBA" {
				probe.rejects = 0
			}
			m := pg03ChainFixture(t, probe)
			t.Setenv("CLEARAPI_PG03_POLICY_KEY", "synthetic-pg03-policy-key-012345678901234567890123456789")
			data, err := os.ReadFile(filepath.Join(directory, name+".json"))
			if err != nil {
				t.Fatal(err)
			}
			var wire struct {
				Headers http.Header `json:"headers"`
				Body    string      `json:"body"`
			}
			if err := json.Unmarshal(data, &wire); err != nil {
				t.Fatal(err)
			}
			// HTTP ingress supplies unmodified signed headers/body to the actual
			// executor manager and drains its final SSE through a response writer.
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				body, err := io.ReadAll(r.Body)
				if err != nil {
					t.Error(err)
					w.WriteHeader(500)
					return
				}
				ctx, opts := capacityOptions("unused")
				opts.Headers, opts.OriginalRequest = r.Header.Clone(), body
				c, _ := gin.CreateTestContext(httptest.NewRecorder())
				c.Request = r
				ctx = context.WithValue(ctx, "gin", c)
				result, err := m.ExecuteStream(ctx, []string{"codex"}, cliproxyexecutor.Request{Model: "synthetic-native", Payload: body}, opts)
				if err != nil {
					t.Error(err)
					w.WriteHeader(403)
					return
				}
				w.Header().Set("Content-Type", "text/event-stream")
				for chunk := range result.Chunks {
					if chunk.Err != nil {
						t.Error(chunk.Err)
						return
					}
					fmt.Fprintf(w, "data: %s\n\n", chunk.Payload)
				}
			})
			req := httptest.NewRequest(http.MethodPost, "/v1/responses", strings.NewReader(wire.Body))
			req.Header = wire.Headers
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, req)
			want := []string{"pg03-A", "pg03-B", "pg03-C"}
			if name == "gateway-DCBA" {
				want = []string{"pg03-D"}
			}
			if response.Code != 200 || !strings.Contains(response.Body.String(), "response.completed") || !reflect.DeepEqual(probe.order, want) || probe.dispatches[want[len(want)-1]] != 1 {
				t.Fatalf("HTTP=%d order=%v dispatch=%v body=%s", response.Code, probe.order, probe.dispatches, response.Body.String())
			}
			previous := ""
			requestID := wire.Headers.Get(pg03RequestHeader)
			for _, id := range want {
				receiptID := poolReceiptIDForTest(requestID, requestID+"-attempt", id)
				data, err := os.ReadFile(filepath.Join(probe.dir, receiptID+".jsonl"))
				if err != nil {
					t.Fatal(err)
				}
				lines := strings.Split(strings.TrimSpace(string(data)), "\n")
				var final receiptEvent
				if err := json.Unmarshal([]byte(lines[len(lines)-1]), &final); err != nil {
					t.Fatal(err)
				}
				if final.Event != "FINAL" || final.PreviousReceiptID != previous {
					t.Fatalf("invalid receipt chain: %+v", final)
				}
				if probe.dispatches[id] == 0 && final.State != "NOT_STARTED" {
					t.Fatalf("rejection state: %s", final.State)
				}
				if probe.dispatches[id] == 1 && (final.State != "STARTED" || final.SSE == nil || final.SSE.ResultState != "COMPLETED") {
					t.Fatalf("success receipt: %+v", final)
				}
				previous = receiptID
			}
			t.Logf("Gateway signed HTTP -> Executor: order=%v dispatch=%v SSE completed", probe.order, probe.dispatches)
		})
	}
}

func TestPG03SSEFallbackChainProofValidation(t *testing.T) {
	for _, mode := range []string{"legacy-parent", "broken-link", "duplicate-account", "started", "unknown", "wrong-request", "consumed-budget", "cancelled", "max-four"} {
		t.Run(mode, func(t *testing.T) {
			probe := &pg03StreamProbe{}
			m := pg03ChainFixture(t, probe)
			ctx, _ := capacityOptions("pg03-proof")
			writer := m.poolGuard.receipts
			chain := &poolSSEFallbackChain{}
			var proofs []*poolSSEZeroDispatchError
			previous := ""
			for i := 0; i < 5; i++ {
				id := fmt.Sprintf("pg03-%c", 'A'+i)
				lease := &poolLease{PoolInFlight: PoolInFlight{AuthID: id, Provider: "codex", Generation: 1}, req: cliproxyexecutor.Request{Model: "synthetic-native"}, receiptID: poolReceiptIDForTest("pg03-proof", "pg03-proof-attempt", id), receiptRequestID: "pg03-proof", attemptID: "pg03-proof-attempt", receiptSSE: true, previousReceiptID: previous}
				if err := writer.begin(lease); err != nil {
					t.Fatal(err)
				}
				final := writer.event(lease, "FINAL", "NOT_STARTED", 2)
				final.SSE = &sseReceiptFinal{DispatchState: "NOT_STARTED", ResultState: "FAILED", EndReason: "account_credential_locally_unavailable"}
				if err := writer.write(final); err != nil {
					t.Fatal(err)
				}
				proofs = append(proofs, &poolSSEZeroDispatchError{final: final})
				previous = final.ReceiptID
			}
			if mode == "legacy-parent" {
				if err := writer.verifyZeroDispatchParent(proofs[1].final); err == nil {
					t.Fatal("legacy C5 verifier accepted multi-level parent")
				}
				return
			}
			if mode == "max-four" {
				for i := 0; i < 4; i++ {
					if err := chain.reject(ctx, proofs[i], writer); err != nil {
						t.Fatal(err)
					}
				}
				if err := chain.reject(ctx, proofs[4], writer); err == nil {
					t.Fatal("fifth proof accepted")
				}
				if chain.count() != 4 {
					t.Fatal("bound exceeded")
				}
				return
			}
			if err := chain.reject(ctx, proofs[0], writer); err != nil {
				t.Fatal(err)
			}
			proof := proofs[1]
			switch mode {
			case "broken-link":
				proof.final.PreviousReceiptID = "other"
			case "duplicate-account":
				proof.final.AccountRef = proofs[0].final.AccountRef
			case "started":
				proof.final.State = "STARTED"
			case "unknown":
				proof.final.State = "UNKNOWN"
			case "wrong-request":
				proof.final.RequestID = "other-request"
			case "consumed-budget":
				ctx.Value(poolAttemptContextKey{}).(*atomicPoolAttempt).CompareAndSwap(false, true)
			case "cancelled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			if err := chain.reject(ctx, proof, writer); err == nil {
				t.Fatal("unsafe proof accepted")
			}
			if chain.count() != 1 {
				t.Fatal("failed proof advanced chain")
			}
		})
	}
}
