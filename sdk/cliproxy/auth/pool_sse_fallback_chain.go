package auth

import (
	"context"
	"errors"

	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
)

const maxPG03SSEFallbackAccounts = 4

// poolSSEFallbackChain is request-local provenance for consecutive, trusted
// zero-dispatch account rejections. It never owns or resets the dispatch
// budget; pool leases remain responsible for that contract.
type poolSSEFallbackChain struct {
	proofs []*poolSSEZeroDispatchError
}

func (c *poolSSEFallbackChain) count() int {
	if c == nil {
		return 0
	}
	return len(c.proofs)
}

func (c *poolSSEFallbackChain) append(proof *poolSSEZeroDispatchError, writer *receiptWriter) error {
	if c == nil || proof == nil || writer == nil || c.count() >= maxPG03SSEFallbackAccounts {
		return ErrPoolGuard
	}
	if err := writer.verifyZeroDispatchChain(c.proofs, proof.final); err != nil {
		return err
	}
	c.proofs = append(c.proofs, proof)
	return nil
}

func (c *poolSSEFallbackChain) reject(ctx context.Context, err error, writer *receiptWriter) error {
	if ctx == nil {
		return ErrPoolGuard
	}
	budget, _ := ctx.Value(poolAttemptContextKey{}).(*atomicPoolAttempt)
	if ctx.Err() != nil || budget == nil || budget.Load() || !isPoolSSEZeroDispatchError(err) || cliproxyexecutor.UpstreamAttempted(ctx) {
		return ErrPoolGuard
	}
	var proof *poolSSEZeroDispatchError
	if !errors.As(err, &proof) {
		return ErrPoolGuard
	}
	return c.append(proof, writer)
}

type poolSSEFallbackChainContextKey struct{}

// Revalidate every ancestor from disk, including the supplied immediate parent.
// The legacy verifier still refuses parents with their own parent receipts.
func (w *receiptWriter) verifyZeroDispatchChain(ancestors []*poolSSEZeroDispatchError, final receiptEvent) error {
	if w == nil || len(ancestors) >= maxPG03SSEFallbackAccounts {
		return ErrPoolGuard
	}
	previous := ""
	accounts := make(map[string]bool)
	ids := make(map[string]bool)
	for i := 0; i <= len(ancestors); i++ {
		event := final
		if i < len(ancestors) {
			if ancestors[i] == nil {
				return ErrPoolGuard
			}
			event = ancestors[i].final
		}
		if event.PreviousReceiptID != previous || accounts[event.AccountRef] || ids[event.ReceiptID] || event.Provider != "codex" || event.RequestID != final.RequestID || event.AttemptID != final.AttemptID || event.CanonicalModel != final.CanonicalModel {
			return ErrPoolGuard
		}
		if err := w.verifyZeroDispatchRecord(event, true); err != nil {
			return err
		}
		previous = event.ReceiptID
		accounts[event.AccountRef], ids[event.ReceiptID] = true, true
	}
	return nil
}
