package auth

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"

	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
)

const poolCapacityReason = "pool_capacity_exhausted"

// A durable capacity refusal stops this business attempt; it is never an A-to-B parent.
type poolCapacityRejection struct{ final receiptEvent }

func (e *poolCapacityRejection) Error() string         { return poolCapacityReason }
func (e *poolCapacityRejection) Unwrap() error         { return ErrPoolGuard }
func (e *poolCapacityRejection) StatusCode() int       { return http.StatusForbidden }
func (e *poolCapacityRejection) DirectResponse() bool  { return true }
func (e *poolCapacityRejection) IsRequestStop() bool   { return true }
func (e *poolCapacityRejection) IsRequestScoped() bool { return true }
func (e *poolCapacityRejection) ResponseBody() []byte {
	f := e.final
	proof := map[string]any{"receipt_id": f.ReceiptID, "request_id": f.RequestID, "attempt_id": f.AttemptID, "account_ref": f.AccountRef, "account_generation": f.AccountGeneration, "account_evidence_id": f.AccountEvidenceID, "canonical_model": f.CanonicalModel, "process_epoch": f.ProcessEpoch, "reason": poolCapacityReason, "sha256": f.SSE.SHA256}
	body, _ := json.Marshal(map[string]any{"error": map[string]any{"code": "pool_admission_required", "message": poolCapacityReason, "type": "security_error", "metadata": map[string]any{"codex_upstream_dispatched": false, "pg02_capacity_receipt": proof}}})
	return body
}

func poolCapacityReceiptID(request, attempt string) string {
	digest := sha256.Sum256([]byte("capacity\n" + request + "\n" + attempt))
	return hex.EncodeToString(digest[:])
}

// Even an incomplete rejection blocks reuse. No request path repairs or overwrites it.
func (w *receiptWriter) receiptExists(id string) (exists bool, resultErr error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.faulted.Load() || !validReceiptID(id) {
		return false, ErrPoolGuard
	}
	dir, err := openReceiptDirectory(w.dir)
	if err != nil {
		return false, err
	}
	defer func() {
		if err := dir.Close(); err != nil && resultErr == nil {
			resultErr = err
		}
	}()
	f, err := openReceiptFile(dir, id+".jsonl", false)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, f.Close()
}

// Caller holds guard.mu and countsMu. The proof holder is never a live lease.
func (executor *poolExecutor) capacityRejection(ctx context.Context, auth *Auth, req cliproxyexecutor.Request, opts cliproxyexecutor.Options, trust PoolTrustRecord, record *PoolGrantFile) error {
	guard := executor.manager.poolGuard
	request, attempt := opts.Headers.Get("X-ClearAPI-PG02-Request"), opts.Headers.Get("X-ClearAPI-PG02-Attempt")
	if guard.receipts == nil || !validReceiptID(request) || !validReceiptID(attempt) || context.Cause(ctx) != nil || ctx.Value(poolSSEFallbackContextKey{}) != nil {
		return ErrPoolGuard
	}
	// A previous account invocation makes a new whole-attempt zero-work claim ambiguous.
	for _, grant := range record.Grants {
		digest := sha256.Sum256([]byte(request + "\n" + attempt + "\n" + grant.AuthID))
		if found, err := guard.receipts.receiptExists(hex.EncodeToString(digest[:])); err != nil || found {
			return ErrPoolGuard
		}
	}
	budget, _ := ctx.Value(poolAttemptContextKey{}).(*atomicPoolAttempt)
	if budget == nil || !budget.CompareAndSwap(false, true) {
		return ErrPoolGuard
	}
	child, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)
	proof := &poolLease{PoolInFlight: PoolInFlight{AuthID: auth.ID, Provider: auth.Provider, Generation: trust.Generation, AuthorizationVersion: trust.AuthorizationVersion}, manager: executor.manager, req: req, ctx: child, cancel: cancel, attemptID: attempt, receiptRequestID: request, receiptID: poolCapacityReceiptID(request, attempt), receiptSSE: true, receiptState: "NOT_STARTED"}
	if err := guard.receipts.begin(proof); err != nil {
		return ErrPoolGuard
	}
	final := guard.receipts.event(proof, "FINAL", "NOT_STARTED", 2)
	final.SSE = &sseReceiptFinal{DispatchState: "NOT_STARTED", ResultState: "FAILED", EndReason: poolCapacityReason}
	unsigned, err := json.Marshal(final)
	if err != nil {
		return ErrPoolGuard
	}
	digest := sha256.Sum256(unsigned)
	final.SSE.SHA256 = hex.EncodeToString(digest[:])
	if err := guard.receipts.write(final); err != nil {
		return ErrPoolGuard
	}
	// Memory provenance alone cannot certify persistence or prior-record integrity.
	if err := guard.receipts.verifyCapacityRejection(final); err != nil {
		return ErrPoolGuard
	}
	return &poolCapacityRejection{final: final}
}

func (w *receiptWriter) verifyCapacityRejection(final receiptEvent) (resultErr error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.faulted.Load() {
		return ErrPoolGuard
	}
	dir, err := openReceiptDirectory(w.dir)
	if err != nil {
		return err
	}
	defer func() {
		if err := dir.Close(); err != nil && resultErr == nil {
			resultErr = err
		}
	}()
	f, err := openReceiptFile(dir, final.ReceiptID+".jsonl", false)
	if err != nil {
		return err
	}
	defer func() {
		if err := f.Close(); err != nil && resultErr == nil {
			resultErr = err
		}
	}()
	data, err := io.ReadAll(io.LimitReader(f, 65537))
	if err != nil || len(data) > 65536 {
		return ErrPoolGuard
	}
	begin := final
	begin.Event, begin.State, begin.Sequence, begin.SSE = "BEGIN", "UNKNOWN", 1, nil
	first, err := json.Marshal(begin)
	if err != nil {
		return err
	}
	last, err := json.Marshal(final)
	if err != nil {
		return err
	}
	expected := append(append(append(first, '\n'), last...), '\n')
	if !bytes.Equal(data, expected) {
		return ErrPoolGuard
	}
	return nil
}
