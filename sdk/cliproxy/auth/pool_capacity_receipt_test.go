package auth

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"testing"

	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
	sdktranslator "github.com/router-for-me/CLIProxyAPI/v8/sdk/translator"
)

func capacityOptions(request string) (context.Context, cliproxyexecutor.Options) {
	opts := cliproxyexecutor.Options{Stream: true, SourceFormat: sdktranslator.FormatOpenAIResponse, OriginalRequest: []byte(`{"stream":true}`), Headers: make(http.Header), Metadata: map[string]any{cliproxyexecutor.RequestPathMetadataKey: "/v1/responses"}}
	opts.Headers.Set("X-ClearAPI-PG02-Request", request)
	opts.Headers.Set("X-ClearAPI-PG02-Attempt", request+"-attempt")
	mac := hmac.New(sha256.New, []byte(os.Getenv("CLEARAPI_PG02_GATEWAY_PROOF_KEY")))
	mac.Write([]byte(request + "\n" + request + "-attempt\nPOST\n/v1/responses\n"))
	mac.Write(opts.OriginalRequest)
	opts.Headers.Set("X-ClearAPI-PG02-Gateway-Proof", hex.EncodeToString(mac.Sum(nil)))
	return context.WithValue(context.Background(), poolAttemptContextKey{}, &atomicPoolAttempt{}), opts
}

func capacityFixture(t *testing.T) (*Manager, *poolExecutor, *Auth, string) {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv(receiptDirEnv, dir)
	t.Setenv("CLEARAPI_PG02_RESPONSES_SSE", "true")
	t.Setenv("CLEARAPI_PG02_HTTP_NON_STREAM", "")
	t.Setenv("CLEARAPI_PG02_PROCESS_EPOCH", "00112233445566778899aabbccddeeff")
	t.Setenv("CLEARAPI_PG02_GATEWAY_PROOF_KEY", "synthetic-proof-key-for-capacity-tests-only")
	m, _, a, _, _ := poolGuardFixture(t, "service")
	return m, m.executors["codex"].(*poolExecutor), a, dir
}

func TestPG02CapacityDurableProofAndReplay(t *testing.T) {
	m, e, a, dir := capacityFixture(t)
	ctx, opts := capacityOptions("holder")
	lease, err := e.begin(ctx, a, cliproxyexecutor.Request{Model: "synthetic-native", Payload: opts.OriginalRequest}, opts, true, true)
	if err != nil {
		t.Fatal(err)
	}
	ctx, opts = capacityOptions("rejected")
	denied, err := e.begin(ctx, a, cliproxyexecutor.Request{Model: "synthetic-native", Payload: opts.OriginalRequest}, opts, true, true)
	var proof *poolCapacityRejection
	if denied != nil || !errors.As(err, &proof) {
		t.Fatal("missing durable capacity refusal", err)
	}
	if isPoolSSEZeroDispatchError(err) {
		t.Fatal("capacity changed A-to-B eligibility")
	}
	if poolAccountingTermination(err, nil) != err {
		t.Fatal("capacity evidence stripped")
	}
	if len(m.PoolInFlightSnapshot()) != 1 {
		t.Fatal("refusal allocated a concurrency lease")
	}
	if err := m.poolGuard.receipts.verifyCapacityRejection(proof.final); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(dir, proof.final.ReceiptID+".jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	var events []receiptEvent
	for _, line := range bytesLines(data) {
		var r receiptEvent
		if err := json.Unmarshal(line, &r); err != nil {
			t.Fatal(err)
		}
		events = append(events, r)
	}
	if len(events) != 2 || events[0].Event != "BEGIN" || events[1].Event != "FINAL" || events[1].State != "NOT_STARTED" || events[1].SSE.EndReason != poolCapacityReason || events[1].SSE.Usage != nil {
		t.Fatal("invalid zero-work proof", events)
	}
	lease.End("test_end")
	// A fresh execution context and a recovered writer must not execute this terminal attempt.
	for _, epoch := range []string{"00112233445566778899aabbccddeeff", "ffeeddccbbaa99887766554433221100"} {
		t.Setenv("CLEARAPI_PG02_PROCESS_EPOCH", epoch)
		writer, err := newReceiptWriter()
		if err != nil {
			t.Fatal(err)
		}
		m.poolGuard.receipts = writer
		ctx, opts = capacityOptions("rejected")
		again, err := e.begin(ctx, a, cliproxyexecutor.Request{Model: "synthetic-native", Payload: opts.OriginalRequest}, opts, true, true)
		if again != nil || err == nil {
			t.Fatal("terminal capacity attempt replayed")
		}
	}
	ctx, opts = capacityOptions("recovered")
	last, err := e.begin(ctx, a, cliproxyexecutor.Request{Model: "synthetic-native", Payload: opts.OriginalRequest}, opts, true, true)
	if err != nil {
		t.Fatal(err)
	}
	last.End("test_end")
}

func bytesLines(data []byte) [][]byte {
	return bytes.Split(bytes.TrimSuffix(data, []byte{'\n'}), []byte{'\n'})
}

func TestPG02CapacityAlreadyStartedNoFalseProof(t *testing.T) {
	m, executor, auth, dir := capacityFixture(t)
	ctx, opts := capacityOptions("already-started")
	lease, err := executor.begin(ctx, auth, cliproxyexecutor.Request{Model: "synthetic-native", Payload: opts.OriginalRequest}, opts, true, true)
	if err != nil {
		t.Fatal(err)
	}
	if err := lease.AuthorizeDispatch(); err != nil {
		t.Fatal(err)
	}
	if err := lease.UpstreamDispatchStarted(); err != nil {
		t.Fatal(err)
	}
	ctx, opts = capacityOptions("already-started")
	_, err = executor.begin(ctx, auth, cliproxyexecutor.Request{Model: "synthetic-native", Payload: opts.OriginalRequest}, opts, true, true)
	var proof *poolCapacityRejection
	if err == nil || errors.As(err, &proof) {
		t.Fatal("started business attempt acquired a zero-work capacity proof")
	}
	lease.End("unknown_after_dispatch")
	data, err := os.ReadFile(filepath.Join(dir, lease.receiptID+".jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	lines := bytesLines(data)
	var final receiptEvent
	if err := json.Unmarshal(lines[len(lines)-1], &final); err != nil {
		t.Fatal(err)
	}
	if len(lines) != 3 || final.State != "STARTED" || final.SSE.ResultState != "UNKNOWN" {
		t.Fatal("started transport downgraded", final)
	}
	if exists, err := m.poolGuard.receipts.receiptExists(poolCapacityReceiptID("already-started", "already-started-attempt")); err != nil || exists {
		t.Fatal("false capacity marker", err)
	}
}

func TestPG02CapacityAmbiguityAndStorageFailure(t *testing.T) {
	for _, mode := range []string{"cancelled", "consumed", "fallback", "missing-dir", "faulted", "prior-account-receipt"} {
		t.Run(mode, func(t *testing.T) {
			m, e, a, dir := capacityFixture(t)
			ctx, opts := capacityOptions("holder")
			hold, err := e.begin(ctx, a, cliproxyexecutor.Request{Model: "synthetic-native", Payload: opts.OriginalRequest}, opts, true, true)
			if err != nil {
				t.Fatal(err)
			}
			ctx, opts = capacityOptions("ambiguous")
			switch mode {
			case "cancelled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			case "consumed":
				ctx.Value(poolAttemptContextKey{}).(*atomicPoolAttempt).Store(true)
			case "fallback":
				ctx = context.WithValue(ctx, poolSSEFallbackContextKey{}, &poolSSEZeroDispatchError{})
			case "missing-dir":
				if err := os.Rename(dir, dir+"-lost"); err != nil {
					t.Fatal(err)
				}
			case "faulted":
				m.poolGuard.receipts.faulted.Store(true)
			case "prior-account-receipt":
				digest := sha256.Sum256([]byte("ambiguous\nambiguous-attempt\n" + a.ID))
				if err := os.WriteFile(filepath.Join(dir, hex.EncodeToString(digest[:])+".jsonl"), []byte("prior ambiguous receipt\n"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			_, err = e.begin(ctx, a, cliproxyexecutor.Request{Model: "synthetic-native", Payload: opts.OriginalRequest}, opts, true, true)
			var proof *poolCapacityRejection
			if err == nil || errors.As(err, &proof) {
				t.Fatal("ambiguous refusal minted proof", err)
			}
			if len(m.PoolInFlightSnapshot()) != 1 {
				t.Fatal("failed refusal changed slots")
			}
			hold.End("test_end")
		})
	}
}

func TestPG02CapacityLeaseEndCancellationRace(t *testing.T) {
	m, e, a, _ := capacityFixture(t)
	for i := range 32 {
		ctx, opts := capacityOptions(fmt.Sprintf("hold-%d", i))
		hold, err := e.begin(ctx, a, cliproxyexecutor.Request{Model: "synthetic-native", Payload: opts.OriginalRequest}, opts, true, true)
		if err != nil {
			t.Fatal(err)
		}
		ctx2, opts2 := capacityOptions(fmt.Sprintf("race-%d", i))
		ctx2, cancel := context.WithCancel(ctx2)
		var result *poolLease
		var refusal error
		var wg sync.WaitGroup
		start := make(chan struct{})
		wg.Add(3)
		go func() { defer wg.Done(); <-start; hold.End("test_end") }()
		go func() { defer wg.Done(); <-start; cancel() }()
		go func() {
			defer wg.Done()
			<-start
			result, refusal = e.begin(ctx2, a, cliproxyexecutor.Request{Model: "synthetic-native", Payload: opts2.OriginalRequest}, opts2, true, true)
		}()
		close(start)
		wg.Wait()
		var proof *poolCapacityRejection
		if errors.As(refusal, &proof) {
			if result != nil || proof.final.State != "NOT_STARTED" {
				t.Fatal("false zero-work proof")
			}
			if err := m.poolGuard.receipts.verifyCapacityRejection(proof.final); err != nil {
				t.Fatal(err)
			}
		} else if result != nil {
			result.End("test_end")
		}
		if len(m.PoolInFlightSnapshot()) != 0 {
			t.Fatal("lease leaked after race")
		}
	}
}
