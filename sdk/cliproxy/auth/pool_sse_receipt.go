package auth

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/gin-gonic/gin"
	"io"
	"net/http"
	"os"
	"strings"

	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/usage"
	sdktranslator "github.com/router-for-me/CLIProxyAPI/v8/sdk/translator"
	"github.com/tidwall/gjson"
)

func poolSSEGatewayProofValid(opts cliproxyexecutor.Options) bool {
	key := os.Getenv("CLEARAPI_PG02_GATEWAY_PROOF_KEY")
	if len(key) < 32 || opts.Headers == nil {
		return false
	}
	request, attempt := opts.Headers.Get("X-ClearAPI-PG02-Request"), opts.Headers.Get("X-ClearAPI-PG02-Attempt")
	if !validReceiptID(request) || !validReceiptID(attempt) {
		return false
	}
	mac := hmac.New(sha256.New, []byte(key))
	mac.Write([]byte(request + "\n" + attempt + "\nPOST\n/v1/responses\n"))
	mac.Write(opts.OriginalRequest)
	proof, err := hex.DecodeString(opts.Headers.Get("X-ClearAPI-PG02-Gateway-Proof"))
	return err == nil && hmac.Equal(proof, mac.Sum(nil))
}

func (m *Manager) AccountPoolGuarded() bool { return m != nil && m.poolGuard != nil }

// This error can only be minted by a live lease after a durable zero-dispatch
// FINAL. Provider errors and storage failures cannot acquire this provenance.
type poolSSEZeroDispatchError struct{ final receiptEvent }

type poolSSEFallbackContextKey struct{}

func (e *poolSSEZeroDispatchError) Error() string {
	return "pool account credential locally unavailable before dispatch"
}
func isPoolSSEZeroDispatchError(err error) bool {
	var proof *poolSSEZeroDispatchError
	return !hasUpstreamExecutionAttempt(err) && errors.As(err, &proof) && proof.final.ReceiptID != ""
}

func (lease *poolLease) LocalAccountUnavailable() error {
	guard := lease.manager.poolGuard
	guard.mu.Lock()
	defer guard.mu.Unlock()
	if !lease.receiptSSE || guard.leases[lease.RequestID] != lease || lease.Dispatched || lease.receiptState != "NOT_STARTED" || lease.receiptFailed || lease.receiptFinal || lease.ctx.Err() != nil {
		return ErrPoolGuard
	}
	if err := lease.writeSSEFinalLocked(nil, "account_credential_locally_unavailable"); err != nil {
		return err
	}
	return &poolSSEZeroDispatchError{final: lease.sseFinalEvent}
}

// Pool SSE admission uses the original protocol and body, never a translated
// stream flag. Service authorization, trust and the dispatch fence still apply.
func poolResponsesSSEAdmitted(ctx context.Context, opts cliproxyexecutor.Options) bool {
	path, _ := opts.Metadata[cliproxyexecutor.RequestPathMetadataKey].(string)
	if ctx != nil {
		if c, ok := ctx.Value("gin").(*gin.Context); ok && c != nil && (c.Request == nil || c.Request.Method != http.MethodPost || c.Request.URL == nil || c.Request.URL.Path != "/v1/responses" || c.Request.Header.Get("Upgrade") != "" || strings.Contains(strings.ToLower(c.Request.Header.Get("Connection")), "upgrade")) {
			return false
		}
	}
	return poolSSEStreamBodyAdmitted(opts.OriginalRequest) && os.Getenv("CLEARAPI_PG02_RESPONSES_SSE") == "true" &&
		!cliproxyexecutor.DownstreamWebsocket(ctx) && opts.Stream && opts.Alt == "" &&
		opts.SourceFormat == sdktranslator.FormatOpenAIResponse && path == "/v1/responses" &&
		opts.Headers.Get("Upgrade") == "" && !strings.Contains(strings.ToLower(opts.Headers.Get("Connection")), "upgrade")
}

func poolSSEStreamBodyAdmitted(body []byte) bool {
	count, valid := 0, true
	gjson.ParseBytes(body).ForEach(func(key, value gjson.Result) bool {
		if strings.EqualFold(key.String(), "stream") {
			count++
			valid = valid && key.String() == "stream" && value.Type == gjson.True
		}
		return true
	})
	return count == 1 && valid && gjson.ValidBytes(body) && gjson.ParseBytes(body).IsObject()
}

// Inspect the actual translated HTTP request before the existing dispatch fence
// and STARTED observer; a protocol rejection retains trusted zero-send metadata.
func (lease *poolLease) ValidateDispatchProtocol(req *http.Request) error {
	reject := func() error { return poolAccountingTermination(ErrPoolGuard, lease) }
	if req == nil || req.URL == nil || req.Method != http.MethodPost || req.Header.Get("Upgrade") != "" || strings.Contains(strings.ToLower(req.Header.Get("Connection")), "upgrade") {
		return reject()
	}
	if !lease.receiptSSE {
		return nil
	}
	if !strings.HasSuffix(req.URL.Path, "/responses") || req.GetBody == nil {
		return reject()
	}
	body, err := req.GetBody()
	if err != nil {
		return reject()
	}
	defer body.Close()
	payload, err := io.ReadAll(body)
	if err != nil || !poolSSEStreamBodyAdmitted(payload) {
		return reject()
	}
	return nil
}

func (lease *poolLease) ResponsesSSE() bool { return lease.receiptSSE }

// PersistResponsesSSEEvent runs on raw provider bytes before translation or
// usage synthesis, and before the terminal event can reach the client.
func (lease *poolLease) PersistResponsesSSEEvent(payload []byte) error {
	if !lease.receiptSSE {
		return nil
	}
	kind := gjson.GetBytes(payload, "type").String()
	switch kind {
	case "response.completed", "response.failed", "response.incomplete", "response.interrupted", "response.cancelled", "response.canceled", "response.done":
	default:
		return nil
	}
	guard := lease.manager.poolGuard
	guard.mu.Lock()
	defer guard.mu.Unlock()
	if guard.leases[lease.RequestID] != lease || lease.receiptState != "STARTED" || lease.receiptFailed || lease.receiptFinal {
		return ErrPoolGuard
	}
	return lease.writeSSEFinalLocked(payload, "provider_terminal")
}

// Caller holds guard.mu; STARTED is retained even when EOF leaves outcome unknown.
func (lease *poolLease) writeSSEFinalLocked(payload []byte, reason string) error {
	w := lease.manager.poolGuard.receipts
	if w == nil || lease.receiptFailed {
		return ErrPoolGuard
	}
	root := gjson.ParseBytes(payload)
	kind := root.Get("type").String()
	result := "UNKNOWN"
	if lease.receiptState == "NOT_STARTED" && reason == "account_credential_locally_unavailable" {
		result = "FAILED"
	}
	switch kind {
	case "response.completed":
		if root.Get("response.status").String() == "completed" {
			result = "COMPLETED"
		}
	case "response.failed":
		result = "FAILED"
	case "response.incomplete", "response.interrupted", "response.cancelled", "response.canceled":
		result = "INTERRUPTED"
	}
	if len(payload) == 0 && lease.ctx != nil && lease.ctx.Err() != nil && lease.receiptState == "STARTED" {
		result, reason = "INTERRUPTED", "context_canceled"
	}
	state := lease.receiptState
	sequence := 2
	if state == "STARTED" {
		sequence = 3
	}
	meter := usage.ParseCodexMetering([]byte(root.Get("response.usage").Raw))
	meter.Final, meter.AttemptID = true, lease.attemptID
	meter.ResponseID = root.Get("response.id").String()
	event := w.event(lease, "FINAL", state, sequence)
	meter.AccountRef, meter.Model = event.AccountRef, event.CanonicalModel
	event.SSE = &sseReceiptFinal{DispatchState: state, ResultState: result, ResponseID: meter.ResponseID, TerminalType: kind, EndReason: reason, Usage: meter}
	canonical, err := json.Marshal(event)
	if err != nil {
		return err
	}
	digest := sha256.Sum256(canonical)
	event.SSE.SHA256 = hex.EncodeToString(digest[:])
	if err = w.write(event); err != nil {
		lease.receiptFailed = true
		lease.cancel(ErrPoolGuard)
		return ErrPoolGuard
	}
	lease.receiptFinal = true
	lease.sseFinalEvent = event
	return nil
}

// Reuse the SSE gate for every pool invocation, including non-stream execution.
// The legacy HTTP contract requires a separate explicit process authorization.
func poolProtocolAdmitted(ctx context.Context, opts cliproxyexecutor.Options, stream bool) bool {
	sse, legacy := os.Getenv("CLEARAPI_PG02_RESPONSES_SSE"), os.Getenv("CLEARAPI_PG02_HTTP_NON_STREAM")
	if (sse != "true" && sse != "" && sse != "false") || (legacy != "true" && legacy != "" && legacy != "false") || (sse == "true" && legacy == "true") {
		return false
	}
	if sse == "true" {
		return stream && poolResponsesSSEAdmitted(ctx, opts) && poolSSEGatewayProofValid(opts)
	}
	return legacy == "true" && !stream && !opts.Stream && !cliproxyexecutor.DownstreamWebsocket(ctx)
}
