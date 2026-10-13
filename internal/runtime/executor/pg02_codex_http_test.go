package executor

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	auth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	exec "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
	translator "github.com/router-for-me/CLIProxyAPI/v8/sdk/translator"
)

// Test-only boundary stimulus: the real manager has already authorized and
// persisted A's BEGIN before this selected credential becomes locally unusable.
// The real Codex executor and receipt writer still perform the entire rejection.
type pg02SSEBoundaryExecutor struct {
	*CodexExecutor
	before func() error
}

func (e *pg02SSEBoundaryExecutor) ExecuteStream(ctx context.Context, selected *auth.Auth, req exec.Request, opts exec.Options) (*exec.StreamResult, error) {
	snapshot := selected.Clone()
	if snapshot.ID == "synthetic-A" {
		if e.before != nil {
			if err := e.before(); err != nil {
				return nil, err
			}
		}
		snapshot.Metadata["access_token"] = ""
	}
	return e.CodexExecutor.ExecuteStream(ctx, snapshot, req, opts)
}

func TestPG02ResponsesSSESafeFallbackAndNoReplay(t *testing.T) {
	for _, mode := range []string{"local-zero-dispatch", "local-final-write-failure", "parent-unavailable-before-B", "started-disconnect", "concurrent-fallback"} {
		t.Run(mode, func(t *testing.T) {
			root := t.TempDir()
			receipts := filepath.Join(root, "receipts")
			authdir := filepath.Join(root, "auths")
			for _, path := range []string{receipts, authdir} {
				if err := os.Mkdir(path, 0700); err != nil {
					t.Fatal(err)
				}
			}
			t.Setenv("CLEARAPI_PG02_RECEIPT_DIR", receipts)
			t.Setenv("CLEARAPI_PG02_RESPONSES_SSE", "true")
			t.Setenv("CLEARAPI_PG02_PROCESS_EPOCH", "00112233445566778899aabbccddeeff")
			proofKey := "synthetic-proof-key-for-local-tests-only"
			t.Setenv("CLEARAPI_PG02_GATEWAY_PROOF_KEY", proofKey)
			t.Setenv("CLEARAPI_POOL_ROLE", "service")
			t.Setenv("CLEARAPI_POOL_EXECUTOR_ID", "synthetic-sse-executor")
			checkpoint, policy := filepath.Join(root, "floor.jsonl"), filepath.Join(root, "grants.json")
			t.Setenv("CLEARAPI_POOL_CHECKPOINT_FILE", checkpoint)
			t.Setenv("CLEARAPI_POOL_ADMISSION_FILE", policy)
			if err := auth.ProvisionPoolCheckpoint(checkpoint, "synthetic-sse-executor"); err != nil {
				t.Fatal(err)
			}
			var aEntries, bEntries atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Chatgpt-Account-Id") == "synthetic-A" {
					aEntries.Add(1)
				} else if r.Header.Get("Chatgpt-Account-Id") == "synthetic-B" {
					bEntries.Add(1)
				} else {
					t.Error("unknown account")
				}
				if mode == "started-disconnect" {
					conn, _, err := w.(http.Hijacker).Hijack()
					if err == nil {
						conn.Close()
					}
					return
				}
				w.Header().Set("Content-Type", "text/event-stream")
				w.Write([]byte("data: {\"type\":\"response.completed\",\"response\":{\"id\":\"r-synthetic\",\"status\":\"completed\",\"output\":[],\"usage\":{\"input_tokens\":10,\"output_tokens\":5,\"total_tokens\":15,\"input_tokens_details\":{\"cached_tokens\":0},\"output_tokens_details\":{\"reasoning_tokens\":0}}}}\n\n"))
			}))
			defer server.Close()
			cfg := &config.Config{AuthDir: authdir}
			manager := auth.NewManager(nil, nil, nil)
			manager.SetConfig(cfg)
			manager.SetRetryConfig(3, 0, 3)
			manager.RegisterExecutor(NewCodexExecutor(cfg))
			parentDigest := sha256.Sum256([]byte("request-synthetic\nattempt-synthetic\nsynthetic-A"))
			parentPath := filepath.Join(receipts, hex.EncodeToString(parentDigest[:])+".jsonl")
			if mode != "started-disconnect" {
				boundary := &pg02SSEBoundaryExecutor{CodexExecutor: NewCodexExecutor(cfg)}
				if mode == "local-final-write-failure" {
					boundary.before = func() error { return os.Chmod(parentPath, 0400) }
				}
				manager.RegisterExecutor(boundary)
			}
			accounts := []*auth.Auth{}
			grant := auth.PoolGrantFile{GuardVersion: auth.PoolGuardVersion, ExecutorID: "synthetic-sse-executor", Revision: 1}
			identities := []auth.PoolIdentityExpectation{}
			for i, label := range []string{"A", "B"} {
				access := "synthetic-unused"
				priority := "0"
				if i == 0 {
					priority = "100"
				}
				account := &auth.Auth{ID: "synthetic-" + label, Provider: "codex", FileName: "synthetic-" + label + ".json", Status: auth.StatusActive, Attributes: map[string]string{auth.AttributeAuthKind: auth.AuthKindOAuth, "base_url": server.URL, "priority": priority}, Metadata: map[string]any{"access_token": access, "account_id": "synthetic-" + label}}
				accounts = append(accounts, account)
				grant.Grants = append(grant.Grants, auth.PoolGrant{AuthID: account.ID, Provider: "codex", CredentialDigest: auth.PoolCredentialDigest(account), Models: []string{"synthetic-native"}, Capabilities: []string{"text_chat", "stream_text", "exact_usage"}, Enabled: true, ExpiresAt: time.Now().Add(10 * time.Minute).Unix(), MaxConcurrency: 1, SourceEvidence: []string{"synthetic-source"}, TestEvidence: []string{"synthetic-test"}})
				identities = append(identities, auth.PoolIdentityExpectation{AuthID: account.ID, Provider: "codex", CredentialDigest: auth.PoolCredentialDigest(account)})
			}
			encoded, _ := json.Marshal(grant)
			if err := os.WriteFile(policy, encoded, 0600); err != nil {
				t.Fatal(err)
			}
			for _, account := range accounts {
				if _, err := manager.Register(context.Background(), account); err != nil {
					t.Fatal(err)
				}
			}
			if err := manager.PromotePoolIdentities(context.Background(), auth.PoolPromotion{ExpectedRevision: 1, Identities: identities}); err != nil {
				t.Fatal(err)
			}
			for _, account := range accounts {
				revision, states, err := manager.PoolTrustSnapshot()
				if err != nil {
					t.Fatal(err)
				}
				identity := auth.PoolIdentityExpectation{AuthID: account.ID, Provider: "codex", CredentialDigest: auth.PoolCredentialDigest(account)}
				for _, state := range states {
					if state.AuthID == account.ID {
						identity.Generation = state.Generation
					}
				}
				if err := manager.GrantPoolModelCapability(context.Background(), auth.PoolModelGrant{ExpectedRevision: revision, Identity: identity, Model: "synthetic-native"}); err != nil {
					t.Fatal(err)
				}
				registry.GetGlobalRegistry().RegisterClient(account.ID, "codex", []*registry.ModelInfo{{ID: "synthetic-native"}})
				defer registry.GetGlobalRegistry().UnregisterClient(account.ID)
			}
			payload := []byte(`{"model":"synthetic-native","input":"synthetic","stream":true}`)
			headers := http.Header{}
			headers.Set("X-ClearAPI-PG02-Request", "request-synthetic")
			headers.Set("X-ClearAPI-PG02-Attempt", "attempt-synthetic")
			mac := hmac.New(sha256.New, []byte(proofKey))
			mac.Write([]byte("request-synthetic\nattempt-synthetic\nPOST\n/v1/responses\n"))
			mac.Write(payload)
			headers.Set("X-ClearAPI-PG02-Gateway-Proof", hex.EncodeToString(mac.Sum(nil)))
			metadata := map[string]any{exec.RequestPathMetadataKey: "/v1/responses"}
			if mode == "parent-unavailable-before-B" {
				metadata[exec.SelectedAuthCallbackMetadataKey] = func(id string) {
					if id == "synthetic-B" {
						if err := os.Chmod(parentPath, 0400); err != nil {
							t.Fatal(err)
						}
					}
				}
			}
			if mode == "concurrent-fallback" {
				var wg sync.WaitGroup
				start := make(chan struct{})
				for i := 0; i < 2; i++ {
					wg.Add(1)
					go func() {
						defer wg.Done()
						<-start
						result, _ := manager.ExecuteStream(context.Background(), []string{"codex"}, exec.Request{Model: "synthetic-native", Payload: payload}, exec.Options{Stream: true, SourceFormat: translator.FormatOpenAIResponse, Headers: headers.Clone(), OriginalRequest: payload, Metadata: map[string]any{exec.RequestPathMetadataKey: "/v1/responses"}})
						if result != nil {
							for range result.Chunks {
							}
						}
					}()
				}
				close(start)
				wg.Wait()
				if aEntries.Load() != 0 || bEntries.Load() > 1 {
					t.Fatalf("concurrent fallback double dispatch A=%d B=%d", aEntries.Load(), bEntries.Load())
				}
				return
			}
			result, err := manager.ExecuteStream(context.Background(), []string{"codex"}, exec.Request{Model: "synthetic-native", Payload: payload}, exec.Options{Stream: true, SourceFormat: translator.FormatOpenAIResponse, Headers: headers, OriginalRequest: payload, Metadata: metadata})
			var output []byte
			if result != nil {
				for chunk := range result.Chunks {
					if chunk.Err != nil {
						err = chunk.Err
					}
					output = append(output, chunk.Payload...)
				}
			}
			if mode == "local-zero-dispatch" {
				if err != nil || aEntries.Load() != 0 || bEntries.Load() != 1 || !strings.Contains(string(output), "response.completed") {
					t.Fatalf("fallback err=%v A=%d B=%d", err, aEntries.Load(), bEntries.Load())
				}
				files, _ := filepath.Glob(filepath.Join(receipts, "*.jsonl"))
				if len(files) != 2 {
					t.Fatalf("fallback did not create both persistent attempts: %d", len(files))
				}
				var zero, started int
				var parentID, previousID string
				evidenceIDs := map[string]bool{}
				for _, file := range files {
					data, _ := os.ReadFile(file)
					lines := strings.Split(strings.TrimSpace(string(data)), "\n")
					var final struct {
						State             string `json:"state"`
						ReceiptID         string `json:"receipt_id"`
						PreviousReceiptID string `json:"previous_receipt_id"`
						RequestID         string `json:"request_id"`
						AttemptID         string `json:"attempt_id"`
						AccountEvidenceID string `json:"account_evidence_id"`
					}
					if json.Unmarshal([]byte(lines[len(lines)-1]), &final) != nil {
						t.Fatal("invalid receipt")
					}
					if final.State == "NOT_STARTED" {
						zero++
						parentID = final.ReceiptID
					}
					if final.State == "STARTED" {
						started++
						previousID = final.PreviousReceiptID
					}
					if len(final.AccountEvidenceID) != 64 || evidenceIDs[final.AccountEvidenceID] {
						t.Fatal("account evidence identity missing or reused")
					}
					evidenceIDs[final.AccountEvidenceID] = true
					if final.RequestID != "request-synthetic" || final.AttemptID != "attempt-synthetic" {
						t.Fatal("business attempt identity changed during fallback")
					}
				}
				if zero != 1 || started != 1 {
					t.Fatalf("proofs zero=%d started=%d", zero, started)
				}
				if parentID == "" || previousID != parentID {
					t.Fatal("B did not persist the exact A parent")
				}
			} else if mode != "started-disconnect" {
				if err == nil || aEntries.Load() != 0 || bEntries.Load() != 0 {
					t.Fatalf("missing durable proof replayed: err=%v A=%d B=%d", err, aEntries.Load(), bEntries.Load())
				}
			} else if err == nil || aEntries.Load() != 1 || bEntries.Load() != 0 {
				t.Fatalf("no-replay err=%v A=%d B=%d", err, aEntries.Load(), bEntries.Load())
			}
		})
	}
}

func TestPG02CodexHTTPExecutionReceipt(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CLEARAPI_PG02_TRANSPORT_DIR", dir)
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.URL.Path != "/responses" {
			t.Error("unexpected local mock path")
		}
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte(`data: {"type":"response.completed","response":{"id":"fixture-response","model":"gpt-5.6-luna","status":"completed","output":[{"type":"message","role":"assistant","content":[{"type":"output_text","text":"fixture"}]}],"usage":{"input_tokens":10,"output_tokens":2,"total_tokens":12}}}` + "\n\n"))
	}))
	defer server.Close()
	a := &auth.Auth{ID: "private-synthetic-account", Provider: "codex", Generation: 52, Metadata: map[string]any{"access_token": "synthetic-only", "base_url": server.URL}}
	headers := http.Header{}
	headers.Set("X-ClearAPI-PG02-Request", "fixture-request")
	headers.Set("X-ClearAPI-PG02-Attempt", "fixture-attempt")
	payload := []byte(`{"model":"gpt-5.6-luna","input":"fixture","stream":false,"tools":[],"max_output_tokens":128}`)
	e := NewCodexExecutor(nil)
	_, err := e.Execute(context.Background(), a, exec.Request{Model: "gpt-5.6-luna", Payload: payload}, exec.Options{SourceFormat: translator.FromString("openai-response"), Headers: headers, OriginalRequest: payload})
	if err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 1 {
		t.Fatalf("local provider HTTP calls=%d", calls.Load())
	}
	files, err := filepath.Glob(filepath.Join(dir, "*.jsonl"))
	if err != nil || len(files) != 1 {
		t.Fatal("receipt missing")
	}
	data, err := os.ReadFile(files[0])
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "synthetic-only") || strings.Contains(string(data), "private-synthetic-account") || strings.Contains(string(data), "Bearer") {
		t.Fatal("sensitive receipt")
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	var final map[string]any
	_ = json.Unmarshal([]byte(lines[len(lines)-1]), &final)
	if final["event"] != "FINAL" || final["state"] != "STARTED" || final["attempt_id"] != "fixture-attempt" {
		t.Fatalf("bad final: %+v", final)
	}
}
