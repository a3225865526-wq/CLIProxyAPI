package auth

import (
	"bufio"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
	sdktranslator "github.com/router-for-me/CLIProxyAPI/v8/sdk/translator"
)

func TestReceiptC4PoolProtocolAdmissionAndFence(t *testing.T) {
	for _, scenario := range []string{"non-stream", "missing-proof", "forged-proof", "alias", "other-sse", "upgrade", "missing-config", "conflicting-config", "invalid-config", "duplicate-stream", "uppercase-stream", "missing-stream", "non-bool-stream", "ws", "legal-sse", "final-config-conflict", "translated-non-stream", "translated-upgrade", "translated-alias", "admission-copy"} {
		t.Run(scenario, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.Chmod(dir, 0700); err != nil {
				t.Fatal(err)
			}
			t.Setenv(receiptDirEnv, dir)
			t.Setenv("CLEARAPI_PG02_RESPONSES_SSE", "true")
			t.Setenv("CLEARAPI_PG02_HTTP_NON_STREAM", "")
			t.Setenv("CLEARAPI_PG02_PROCESS_EPOCH", "00112233445566778899aabbccddeeff")
			t.Setenv("CLEARAPI_PG02_GATEWAY_PROOF_KEY", "synthetic-proof-key-for-local-unit-tests-only")
			m, probe, a, _, _ := poolGuardFixture(t, "service")
			opts := cliproxyexecutor.Options{Stream: true, SourceFormat: sdktranslator.FormatOpenAIResponse, OriginalRequest: []byte(`{"stream":true}`), Headers: make(http.Header), Metadata: map[string]any{cliproxyexecutor.RequestPathMetadataKey: "/v1/responses"}}
			opts.Headers.Set("X-ClearAPI-PG02-Request", "c4-request")
			opts.Headers.Set("X-ClearAPI-PG02-Attempt", "c4-attempt")
			stream := true
			ctx := context.WithValue(context.Background(), poolAttemptContextKey{}, &atomicPoolAttempt{})
			switch scenario {
			case "non-stream":
				stream = false
				opts.Stream = false
				opts.OriginalRequest = []byte(`{"stream":false}`)
			case "alias":
				opts.SourceFormat = sdktranslator.FormatCodex
			case "other-sse":
				opts.Metadata[cliproxyexecutor.RequestPathMetadataKey] = "/v1/messages"
			case "upgrade":
				opts.Headers.Set("Upgrade", "websocket")
			case "missing-config":
				t.Setenv("CLEARAPI_PG02_RESPONSES_SSE", "")
			case "conflicting-config":
				t.Setenv("CLEARAPI_PG02_HTTP_NON_STREAM", "true")
			case "invalid-config":
				t.Setenv("CLEARAPI_PG02_RESPONSES_SSE", "TRUE")
			case "duplicate-stream":
				opts.OriginalRequest = []byte(`{"stream":true,"stream":false}`)
			case "uppercase-stream":
				opts.OriginalRequest = []byte(`{"Stream":true}`)
			case "missing-stream":
				opts.OriginalRequest = []byte(`{}`)
			case "non-bool-stream":
				opts.OriginalRequest = []byte(`{"stream":"true"}`)
			case "ws":
				ctx = cliproxyexecutor.WithDownstreamWebsocket(ctx)
			}
			mac := hmac.New(sha256.New, []byte(os.Getenv("CLEARAPI_PG02_GATEWAY_PROOF_KEY")))
			mac.Write([]byte("c4-request\nc4-attempt\nPOST\n/v1/responses\n"))
			mac.Write(opts.OriginalRequest)
			opts.Headers.Set("X-ClearAPI-PG02-Gateway-Proof", hex.EncodeToString(mac.Sum(nil)))
			if scenario == "missing-proof" {
				opts.Headers.Del("X-ClearAPI-PG02-Gateway-Proof")
			}
			if scenario == "forged-proof" {
				opts.Headers.Set("X-ClearAPI-PG02-Gateway-Proof", strings.Repeat("0", 64))
			}
			lease, err := m.executors["codex"].(*poolExecutor).begin(ctx, a, cliproxyexecutor.Request{Model: "synthetic-native", Payload: opts.OriginalRequest}, opts, stream, true)
			admitted := scenario == "legal-sse" || scenario == "final-config-conflict" || strings.HasPrefix(scenario, "translated-") || scenario == "admission-copy"
			if !admitted {
				if !errors.Is(err, ErrPoolGuard) {
					t.Fatal("expected protocol denial", err)
				}
				if lease != nil {
					t.Fatal("denied request acquired lease")
				}
			} else {
				if err != nil {
					t.Fatal(err)
				}
				body := `{"stream":true}`
				if scenario == "final-config-conflict" {
					t.Setenv("CLEARAPI_PG02_HTTP_NON_STREAM", "true")
				}
				if scenario == "translated-non-stream" {
					body = `{"stream":false}`
				}
				req, errReq := http.NewRequest(http.MethodPost, "http://127.0.0.1/backend/responses", strings.NewReader(body))
				if errReq != nil {
					t.Fatal(errReq)
				}
				if scenario == "translated-upgrade" {
					req.Header.Set("Upgrade", "websocket")
				}
				if scenario == "translated-alias" {
					req.URL.Path = "/messages"
				}
				if scenario == "admission-copy" {
					opts.OriginalRequest[0] = 'x'
					opts.Headers.Set("X-ClearAPI-PG02-Gateway-Proof", "forged")
					opts.Metadata[cliproxyexecutor.RequestPathMetadataKey] = "/alias"
				}
				err = cliproxyexecutor.BeforeUpstreamDispatch(lease.ctx, req)
				if scenario == "legal-sse" || scenario == "admission-copy" {
					if err != nil {
						t.Fatal(err)
					}
					if err := cliproxyexecutor.MarkUpstreamDispatchStarted(lease.ctx); err != nil {
						t.Fatal(err)
					}
				} else {
					if err == nil {
						t.Fatal("final protocol mismatch accepted")
					}
					if lease.Dispatched {
						t.Fatal("protocol mismatch consumed dispatch")
					}
					if ctx.Value(poolAttemptContextKey{}).(*atomicPoolAttempt).Load() {
						t.Fatal("protocol mismatch consumed attempt budget")
					}
				}
				lease.End("test-end")
			}
			if probe.calls.Load() != 0 {
				t.Fatal("unexpected provider invocation")
			}
			files, err := filepath.Glob(filepath.Join(dir, "*.jsonl"))
			if err != nil {
				t.Fatal(err)
			}
			for _, file := range files {
				body, err := os.ReadFile(file)
				if err != nil {
					t.Fatal(err)
				}
				if scenario != "legal-sse" && scenario != "admission-copy" {
					if strings.Contains(string(body), `"event":"STARTED"`) {
						t.Fatal("protocol rejection produced false STARTED")
					}
				}
			}
			if len(m.PoolInFlightSnapshot()) != 0 {
				t.Fatal("lease leaked")
			}
		})
	}
}

func TestReceiptResponsesSSETerminalPersistence(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux receipt contract")
	}
	for _, mode := range []string{"completed", "missing", "zero", "eof", "failed", "final-write-failure"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.Chmod(dir, 0700); err != nil {
				t.Fatal(err)
			}
			t.Setenv(receiptDirEnv, dir)
			t.Setenv("CLEARAPI_PG02_RESPONSES_SSE", "true")
			t.Setenv("CLEARAPI_PG02_PROCESS_EPOCH", "00112233445566778899aabbccddeeff")
			t.Setenv("CLEARAPI_PG02_GATEWAY_PROOF_KEY", "synthetic-proof-key-for-local-unit-tests-only")
			m, _, a, _, _ := poolGuardFixture(t, "service")
			wrapped := m.executors["codex"].(*poolExecutor)
			ctx := context.WithValue(context.Background(), poolAttemptContextKey{}, &atomicPoolAttempt{})
			opts := cliproxyexecutor.Options{Stream: true, SourceFormat: sdktranslator.FormatOpenAIResponse, OriginalRequest: []byte(`{"stream":true}`), Metadata: map[string]any{cliproxyexecutor.RequestPathMetadataKey: "/v1/responses"}}
			opts.Headers = http.Header{"X-Clearapi-Pg02-Attempt": []string{"persistent-attempt"}, "X-Clearapi-Pg02-Request": []string{"persistent-request"}}
			mac := hmac.New(sha256.New, []byte(os.Getenv("CLEARAPI_PG02_GATEWAY_PROOF_KEY")))
			mac.Write([]byte("persistent-request\npersistent-attempt\nPOST\n/v1/responses\n"))
			mac.Write(opts.OriginalRequest)
			opts.Headers.Set("X-ClearAPI-PG02-Gateway-Proof", hex.EncodeToString(mac.Sum(nil)))
			lease, err := wrapped.begin(ctx, a, cliproxyexecutor.Request{Model: "synthetic-native", Payload: []byte(`{}`)}, opts, true, true)
			if err != nil {
				t.Fatal(err)
			}
			if err := lease.AuthorizeDispatch(); err != nil {
				t.Fatal(err)
			}
			if err := lease.UpstreamDispatchStarted(); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(dir, lease.receiptID+".jsonl")
			if mode == "final-write-failure" {
				if err := os.Chmod(path, 0400); err != nil {
					t.Fatal(err)
				}
			}
			if mode != "eof" {
				terminal := `{"type":"response.completed","response":{"id":"r1","status":"completed"}}
`
				if mode == "completed" || mode == "zero" || mode == "final-write-failure" {
					terminal = `{"type":"response.completed","response":{"id":"r1","status":"completed","usage":{"input_tokens":0,"output_tokens":0,"total_tokens":0,"input_tokens_details":{"cached_tokens":0},"output_tokens_details":{"reasoning_tokens":0}}}}`
				}
				if mode == "failed" {
					terminal = `{"type":"response.failed","response":{"id":"r1","status":"failed"}}`
				}
				err = lease.PersistResponsesSSEEvent([]byte(terminal))
				if mode == "final-write-failure" {
					if err == nil {
						t.Fatal("expected receipt persistence failure")
					}
					if !lease.receiptFailed {
						t.Fatal("failure not retained")
					}
					if lease.receiptFinal {
						t.Fatal("false durable final")
					}
					lease.End("failed")
					return
				}
				if err != nil {
					t.Fatal(err)
				}
				if lease.PersistResponsesSSEEvent([]byte(terminal)) == nil {
					t.Fatal("duplicate FINAL accepted")
				}
			}
			lease.End("stream_end")
			lease.End("duplicate_end")
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			lines := strings.Split(strings.TrimSpace(string(data)), "\n")
			if len(lines) != 3 {
				t.Fatalf("events = %d", len(lines))
			}
			var final receiptEvent
			if err := json.Unmarshal([]byte(lines[2]), &final); err != nil {
				t.Fatal(err)
			}
			if final.State != "STARTED" {
				t.Fatal("STARTED was lost")
			}
			if final.Path != "HTTP_RESPONSES_SSE" {
				t.Fatal("wrong receipt protocol")
			}
			if final.Schema != 2 {
				t.Fatal("wrong receipt schema")
			}
			if final.SSE == nil {
				t.Fatal("missing SSE evidence")
			}
			if final.SSE.DispatchState != "STARTED" {
				t.Fatal("wrong dispatch state")
			}
			result := "COMPLETED"
			if mode == "eof" {
				result = "UNKNOWN"
			}
			if mode == "failed" {
				result = "FAILED"
			}
			if final.SSE.ResultState != result {
				t.Fatalf("result = %s want %s", final.SSE.ResultState, result)
			}
			if len(final.SSE.SHA256) != 64 {
				t.Fatal("receipt digest missing")
			}
			if mode == "zero" || mode == "completed" {
				if final.SSE.Usage.Status != "exact" {
					t.Fatal("zero usage not preserved")
				}
			} else {
				if final.SSE.Usage.Status != "unavailable" {
					t.Fatal("missing usage synthesized")
				}
			}
		})
	}
}

func TestReceiptResponsesSSEProtocolAliasesRejected(t *testing.T) {
	t.Setenv("CLEARAPI_PG02_RESPONSES_SSE", "true")
	good := cliproxyexecutor.Options{Stream: true, SourceFormat: sdktranslator.FormatOpenAIResponse, OriginalRequest: []byte(`{"stream":true}`), Metadata: map[string]any{cliproxyexecutor.RequestPathMetadataKey: "/v1/responses"}}
	if !poolResponsesSSEAdmitted(context.Background(), good) {
		t.Fatal("explicit SSE denied")
	}
	for _, format := range []sdktranslator.Format{sdktranslator.FormatCodex, sdktranslator.FormatOpenAI, "responses", "openai-responses", "OPENAI-RESPONSE", ""} {
		bad := good
		bad.SourceFormat = format
		if poolResponsesSSEAdmitted(context.Background(), bad) {
			t.Fatalf("protocol alias accepted: %s", format)
		}
	}
	t.Setenv("CLEARAPI_PG02_RESPONSES_SSE", "")
	if poolResponsesSSEAdmitted(context.Background(), good) {
		t.Fatal("default SSE gate open")
	}
}

func TestReceiptWriterDisabledByDefault(t *testing.T) {
	t.Setenv(receiptDirEnv, "")
	writer, err := newReceiptWriter()
	if err != nil || writer != nil {
		t.Fatalf("newReceiptWriter() = (%v, %v), want (nil, nil)", writer, err)
	}
}

func TestReceiptWriterEmitsBoundEvents(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("receipt process attestation requires Linux")
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv(receiptDirEnv, dir)
	writer, err := newReceiptWriter()
	if err != nil {
		t.Fatal(err)
	}
	lease := &poolLease{PoolInFlight: PoolInFlight{RequestID: 41, AuthID: "synthetic", Provider: "codex", Generation: 7}, req: cliproxyexecutor.Request{Model: "synthetic-native"}, ctx: nil, receiptID: "receipt-test", receiptState: "NOT_STARTED"}
	if err := writer.begin(lease); err != nil {
		t.Fatal(err)
	}
	if err := writer.started(lease); err != nil {
		t.Fatal(err)
	}
	lease.receiptState = "STARTED"
	if err := writer.final(lease, lease.receiptState); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(filepath.Join(dir, "receipt-test.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if errClose := file.Close(); errClose != nil {
			t.Error(errClose)
		}
	}()
	var events []map[string]any
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		var event map[string]any
		if err := json.Unmarshal(scanner.Bytes(), &event); err != nil {
			t.Fatal(err)
		}
		events = append(events, event)
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	if len(events) != 3 || events[0]["event"] != "BEGIN" || events[1]["event"] != "STARTED" || events[2]["event"] != "FINAL" {
		t.Fatalf("events = %#v", events)
	}
	for _, event := range events {
		if event["attempt_id"] != "41" || event["account_generation"] != float64(7) || event["executor_binary_sha256"] != writer.binarySHA || event["process_epoch"] != writer.processEpoch {
			t.Fatalf("unbound event = %#v", event)
		}
	}
}

func TestReceiptWriterRejectsUnsafeDirectory(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0755); err != nil {
		t.Fatal(err)
	}
	t.Setenv(receiptDirEnv, dir)
	if writer, err := newReceiptWriter(); err == nil || writer != nil {
		t.Fatalf("newReceiptWriter() = (%v, %v), want rejection", writer, err)
	}
}

func TestReceiptWriterFailsClosedWhenStorageDisappears(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("receipt process attestation requires Linux")
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv(receiptDirEnv, dir)
	writer, err := newReceiptWriter()
	if err != nil {
		t.Fatal(err)
	}
	lease := &poolLease{PoolInFlight: PoolInFlight{RequestID: 9, AuthID: "synthetic", Provider: "codex", Generation: 1}, req: cliproxyexecutor.Request{Model: "synthetic-native"}, receiptID: "receipt-failure", receiptState: "NOT_STARTED"}
	if err := writer.begin(lease); err != nil {
		t.Fatal(err)
	}
	removed := filepath.Join(t.TempDir(), "removed")
	if err := os.Rename(dir, removed); err != nil {
		t.Fatal(err)
	}
	if err := writer.started(lease); err == nil {
		t.Fatal("expected storage failure")
	}
	if !writer.faulted.Load() {
		t.Fatal("writer did not enter fail-closed state")
	}
}

func TestReceiptLeaseWebsocketConnectFailsClosed(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("receipt process attestation requires Linux")
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv(receiptDirEnv, dir)
	m, _, a, _, _ := poolGuardFixture(t, "service")
	wrapped := m.executors["codex"].(*poolExecutor)
	budget := &atomicPoolAttempt{}
	ctx := context.WithValue(context.Background(), poolAttemptContextKey{}, budget)
	lease, err := wrapped.begin(ctx, a, cliproxyexecutor.Request{Model: "synthetic-native", Payload: []byte(`{}`)}, cliproxyexecutor.Options{}, false, true)
	if err != nil {
		t.Fatal(err)
	}
	if lease.AuthorizeConnect() == nil || lease.Dispatched || budget.Load() {
		t.Fatal("receipt-enabled websocket handshake did not fail closed before transport")
	}
	lease.End("connect_rejected")
	body, err := os.ReadFile(filepath.Join(dir, lease.receiptID+".jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(body)), "\n")
	var final receiptEvent
	if len(lines) != 2 || json.Unmarshal([]byte(lines[1]), &final) != nil || final.Event != "FINAL" || final.State != "NOT_STARTED" {
		t.Fatalf("rejected connect produced false transport evidence: %s", body)
	}
}

func TestReceiptLeaseFenceIsNotTransportEvidence(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("receipt process attestation requires Linux")
	}
	for _, mode := range []string{"not-started", "fence-only", "started-write-failure", "started", "tampered-begin"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.Chmod(dir, 0700); err != nil {
				t.Fatal(err)
			}
			t.Setenv(receiptDirEnv, dir)
			m, _, a, _, _ := poolGuardFixture(t, "service")
			wrapped := m.executors["codex"].(*poolExecutor)
			ctx := context.WithValue(context.Background(), poolAttemptContextKey{}, &atomicPoolAttempt{})
			lease, err := wrapped.begin(ctx, a, cliproxyexecutor.Request{Model: "synthetic-native", Payload: []byte(`{}`)}, cliproxyexecutor.Options{}, false, true)
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(dir, lease.receiptID+".jsonl")
			if mode != "not-started" {
				if err := lease.AuthorizeDispatch(); err != nil {
					t.Fatal(err)
				}
				if lease.receiptState != "UNKNOWN" {
					t.Fatal("fence incorrectly certified transport")
				}
			}
			if mode == "started-write-failure" {
				if err := os.Chmod(path, 0400); err != nil {
					t.Fatal(err)
				}
			}
			if mode == "tampered-begin" {
				body, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				body = []byte(strings.Replace(string(body), `"schema":1`, `"schema":0`, 1))
				if err := os.WriteFile(path, body, 0600); err != nil {
					t.Fatal(err)
				}
			}
			failed := mode == "started-write-failure" || mode == "tampered-begin"
			if failed || mode == "started" {
				err := cliproxyexecutor.MarkUpstreamDispatchStarted(lease.ctx)
				if (err != nil) != failed {
					t.Fatalf("transport observer error = %v", err)
				}
			}
			if mode != "not-started" && lease.AuthorizeDispatch() == nil {
				t.Fatal("second dispatch authorized")
			}
			lease.End("completed")
			lease.End("duplicate")
			if len(m.poolGuard.leases) != 0 || m.poolGuard.counts[a.ID] != 0 {
				t.Fatal("lease completion is not idempotent")
			}
			if failed {
				if !m.poolGuard.receipts.faulted.Load() || lease.receiptState != "UNKNOWN" {
					t.Fatal("storage failure did not remain UNKNOWN/fail-closed")
				}
				return
			}
			body, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			var final receiptEvent
			lines := strings.Split(strings.TrimSpace(string(body)), "\n")
			if err := json.Unmarshal([]byte(lines[len(lines)-1]), &final); err != nil {
				t.Fatal(err)
			}
			state := map[string]string{"not-started": "NOT_STARTED", "fence-only": "UNKNOWN", "started": "STARTED"}[mode]
			if final.Event != "FINAL" || final.State != state || final.Sequence != len(lines) {
				t.Fatalf("incorrect final receipt: %+v", final)
			}
		})
	}
}
