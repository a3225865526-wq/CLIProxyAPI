package auth

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"

	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
)

// Only a fully exhausted signed policy can reuse the existing zero-dispatch
// accounting response. A terminal account's proof alone never authorizes it.
func (m *Manager) pg03ZeroDispatchRefund(ctx context.Context, policy *pg03PolicySnapshot, ids []string, err error) error {
	if ctx == nil || ctx.Err() != nil || !isPoolSSEZeroDispatchError(err) || m.poolGuard == nil || m.poolGuard.receipts == nil {
		return err
	}
	budget, _ := ctx.Value(poolAttemptContextKey{}).(*atomicPoolAttempt)
	if budget == nil || budget.Load() || cliproxyexecutor.UpstreamAttempted(ctx) {
		return err
	}
	if policy == nil || len(ids) < 2 || len(ids) != len(policy.AccountOrder) || policy.MaxFallbackCount+1 < len(ids) {
		return err
	}
	var terminal *poolSSEZeroDispatchError
	if !errors.As(err, &terminal) {
		return err
	}
	ancestors := make([]*poolSSEZeroDispatchError, 0, len(ids)-1)
	for i, id := range ids {
		digest := sha256.Sum256([]byte(policy.RequestID + "\n" + policy.RequestID + "-attempt\n" + id))
		receiptID := hex.EncodeToString(digest[:])
		proof := terminal
		if i < len(ids)-1 {
			var verifyErr error
			proof, verifyErr = m.poolGuard.receipts.pg03RefundAncestor(receiptID)
			if verifyErr != nil {
				return err
			}
		}
		account := sha256.Sum256([]byte(id))
		final := proof.final
		if final.ReceiptID != receiptID || final.AccountRef != hex.EncodeToString(account[:]) || final.RequestID != policy.RequestID || final.AttemptID != policy.RequestID+"-attempt" || final.CanonicalModel != policy.ModelName {
			return err
		}
		if i < len(ids)-1 {
			ancestors = append(ancestors, proof)
		}
	}
	if m.poolGuard.receipts.verifyZeroDispatchChain(ancestors, terminal.final) != nil || ctx.Err() != nil || budget.Load() || cliproxyexecutor.UpstreamAttempted(ctx) {
		return err
	}
	return poolAccountingTermination(ErrPoolGuard, nil)
}

// Read through the same private-file checks as the frozen receipt verifier.
// The complete chain is subsequently revalidated against these disk bytes.
func (w *receiptWriter) pg03RefundAncestor(receiptID string) (proof *poolSSEZeroDispatchError, resultErr error) {
	directory, err := openReceiptDirectory(w.dir)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err := directory.Close(); err != nil && resultErr == nil {
			resultErr = err
		}
	}()
	file, err := openReceiptFile(directory, receiptID+".jsonl", false)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err := file.Close(); err != nil && resultErr == nil {
			resultErr = err
		}
	}()
	data, err := io.ReadAll(io.LimitReader(file, 65537))
	if err != nil || len(data) > 65536 {
		return nil, ErrPoolGuard
	}
	lines := bytes.Split(bytes.TrimSpace(data), []byte("\n"))
	if len(lines) != 2 {
		return nil, ErrPoolGuard
	}
	proof = &poolSSEZeroDispatchError{}
	if json.Unmarshal(lines[1], &proof.final) != nil {
		return nil, ErrPoolGuard
	}
	if proof.final.SSE == nil {
		return nil, ErrPoolGuard
	}
	checksum := proof.final.SSE.SHA256
	proof.final.SSE.SHA256 = ""
	canonical, err := json.Marshal(proof.final)
	proof.final.SSE.SHA256 = checksum
	digest := sha256.Sum256(canonical)
	if err != nil || checksum != hex.EncodeToString(digest[:]) {
		return nil, ErrPoolGuard
	}
	return proof, nil
}
