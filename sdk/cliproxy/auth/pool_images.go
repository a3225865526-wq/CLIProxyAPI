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
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
	"github.com/tidwall/gjson"
)

// PG03 Images Contract v1 (executor side).
//
// This is an explicit, versioned branch next to the Responses SSE contract. It
// does not change the v1 policy wire format: a different header set, a
// different signature domain and a different key are used, so a Responses
// signed payload can never authorize an image generation and vice versa.
const (
	pg03ImagesPolicyHeader    = "X-ClearAPI-PG03-Images-Policy"
	pg03ImagesSignatureHeader = "X-ClearAPI-PG03-Images-Signature"
	pg03ImagesRequestHeader   = "X-ClearAPI-PG03-Images-Request"
	pg03ImagesAttemptHeader   = "X-ClearAPI-PG03-Images-Attempt"

	pg03ImagesSignatureDomain = "clearapi-pg03-images-v1\n"
	pg03ImagesOperation       = "images.generate"
	pg03ImagesPath            = "/v1/images/generations"

	// ImagePoolCapability is the operation-level capability an account must hold
	// in addition to the existing grant floor. Text chat capability is not
	// evidence for image generation.
	ImagePoolCapability = "image_generation"

	// Images result storage. Receipts stay JSONL metadata; the payload is a
	// separate private file so a multi-megabyte body never enters the receipt.
	imagesResultDirEnv = "CLEARAPI_PG03_IMAGE_RESULT_DIR"
	imagesModeEnv      = "CLEARAPI_PG03_IMAGES"
)

// pg03ImagesPolicySnapshot is the v1 canonical wire format for images. Field
// order is part of the signature; the Gateway marshals the same struct shape.
type pg03ImagesPolicySnapshot struct {
	Schema           int      `json:"schema"`
	Operation        string   `json:"operation"`
	PolicyID         int      `json:"policy_id"`
	PoolID           string   `json:"pool_id"`
	ModelName        string   `json:"model_name"`
	BaseModel        string   `json:"base_model"`
	AccountOrder     []string `json:"account_order"`
	MaxFallbackCount int      `json:"max_fallback_count"`
	RequestID        string   `json:"request_id"`
	AttemptID        string   `json:"attempt_id"`
	Method           string   `json:"method"`
	Path             string   `json:"path"`
	BodyDigest       string   `json:"body_digest"`
	IssuedAt         int64    `json:"issued_at"`
}

// imagesReceiptFinal is the schema-3 business result attached to a FINAL
// receipt. It carries references and counts only, never image bytes.
type imagesReceiptFinal struct {
	DispatchState      string `json:"dispatch_state"`
	ResultState        string `json:"result_state"`
	RequestedCount     int    `json:"requested_count"`
	ResultCount        int    `json:"result_count"`
	BillableImageCount int    `json:"billable_image_count"`
	Partial            bool   `json:"partial"`
	ResultRef          string `json:"result_ref,omitempty"`
	ResultSHA256       string `json:"result_sha256,omitempty"`
	ResultBytes        int64  `json:"result_bytes,omitempty"`
	ResponseFormat     string `json:"response_format,omitempty"`
	EndReason          string `json:"end_reason"`
	UsageState         string `json:"usage_state"`
}

func imagesModeEnabled() bool { return os.Getenv(imagesModeEnv) == "true" }

// imagesRequestAdmitted is the transport shape check. It runs before account
// selection, so a malformed or translated request never acquires a lease.
func imagesRequestAdmitted(ctx context.Context, opts cliproxyexecutor.Options) bool {
	if !imagesModeEnabled() {
		return false
	}
	path, _ := opts.Metadata[cliproxyexecutor.RequestPathMetadataKey].(string)
	if path != pg03ImagesPath || opts.Stream || opts.Alt != "" {
		return false
	}
	if ctx != nil {
		if c, ok := ctx.Value("gin").(*gin.Context); ok && c != nil {
			if c.Request == nil || c.Request.Method != http.MethodPost || c.Request.URL == nil || c.Request.URL.Path != pg03ImagesPath {
				return false
			}
		}
	}
	body := opts.OriginalRequest
	if len(body) == 0 || len(body) > 1024*1024 || !gjson.ValidBytes(body) || !gjson.ParseBytes(body).IsObject() {
		return false
	}
	// v1 is exactly one non-streaming image. A different count is a candidate
	// incompatibility, never a silent clamp or an implicit multi-generation.
	if n := gjson.GetBytes(body, "n"); n.Exists() && (n.Type != gjson.Number || n.Int() != 1) {
		return false
	}
	return gjson.GetBytes(body, "model").Type == gjson.String
}

// verifyPG03ImagesPolicy authenticates the signed images snapshot. A present
// but invalid snapshot can never fall back to legacy selection.
func (m *Manager) verifyPG03ImagesPolicy(ctx context.Context, providers []string, opts cliproxyexecutor.Options) (*pg03ImagesPolicySnapshot, []string, error) {
	headers := opts.Headers
	if ctx == nil {
		ctx = context.Background()
	}
	if c, ok := ctx.Value("gin").(*gin.Context); ok && c != nil && c.Request != nil {
		headers = c.Request.Header
	}
	present := false
	for _, name := range []string{pg03ImagesPolicyHeader, pg03ImagesSignatureHeader, pg03ImagesRequestHeader, pg03ImagesAttemptHeader} {
		if _, exists := headers[http.CanonicalHeaderKey(name)]; exists {
			present = true
		}
	}
	if !present {
		// A request without the images headers is not a controlled images
		// operation. Ordinary image endpoints keep their existing routing; the
		// lease admission below refuses to run a codex-pool image request that
		// was never signed.
		return nil, nil, nil
	}
	if !isPoolAttemptContext(ctx) || !imagesRequestAdmitted(ctx, opts) || len(providers) != 1 || providers[0] != "codex" || m.poolGuard == nil || m.HomeEnabled() || m.hasPluginScheduler() {
		return nil, nil, ErrPoolGuard
	}
	for _, name := range []string{pg03ImagesPolicyHeader, pg03ImagesSignatureHeader, pg03ImagesRequestHeader, pg03ImagesAttemptHeader} {
		if len(headers.Values(name)) != 1 || headers.Get(name) == "" {
			return nil, nil, ErrPoolGuard
		}
	}
	key := os.Getenv("CLEARAPI_PG03_IMAGES_POLICY_KEY")
	encoded := headers.Get(pg03ImagesPolicyHeader)
	if len(key) < 32 || len(encoded) > 8192 {
		return nil, nil, ErrPoolGuard
	}
	payload, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return nil, nil, ErrPoolGuard
	}
	signature, err := hex.DecodeString(headers.Get(pg03ImagesSignatureHeader))
	if err != nil {
		return nil, nil, ErrPoolGuard
	}
	mac := hmac.New(sha256.New, []byte(key))
	mac.Write([]byte(pg03ImagesSignatureDomain))
	mac.Write(payload)
	if !hmac.Equal(signature, mac.Sum(nil)) {
		return nil, nil, ErrPoolGuard
	}
	var policy pg03ImagesPolicySnapshot
	if json.Unmarshal(payload, &policy) != nil {
		return nil, nil, ErrPoolGuard
	}
	canonical, err := json.Marshal(policy)
	if err != nil || !equalBytes(canonical, payload) {
		return nil, nil, ErrPoolGuard
	}
	digest := sha256.Sum256(opts.OriginalRequest)
	requestPath, _ := opts.Metadata[cliproxyexecutor.RequestPathMetadataKey].(string)
	now := time.Now().Unix()
	if policy.Schema != 2 || policy.Operation != pg03ImagesOperation || policy.PolicyID <= 0 || policy.PoolID == "" || policy.BaseModel == "" || policy.Method != http.MethodPost || policy.Path != requestPath || policy.Path != pg03ImagesPath || policy.RequestID == "" || len(policy.RequestID) > 128 || policy.AttemptID == "" || len(policy.AttemptID) > 128 || policy.RequestID != headers.Get(pg03ImagesRequestHeader) || policy.AttemptID != headers.Get(pg03ImagesAttemptHeader) || policy.ModelName != gjson.GetBytes(opts.OriginalRequest, "model").String() || policy.BodyDigest != hex.EncodeToString(digest[:]) || policy.IssuedAt > now+30 || policy.IssuedAt < now-300 || policy.MaxFallbackCount < 0 || policy.MaxFallbackCount > 3 || len(policy.AccountOrder) == 0 || len(policy.AccountOrder) > 4 {
		return nil, nil, ErrPoolGuard
	}
	ids := make([]string, 0, len(policy.AccountOrder))
	seenRefs, seenIDs := make(map[string]bool), make(map[string]bool)
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, ref := range policy.AccountOrder {
		if ref == "" || ref != strings.TrimSpace(ref) || seenRefs[ref] {
			return nil, nil, ErrPoolGuard
		}
		seenRefs[ref] = true
		id, count := "", 0
		for _, account := range m.auths {
			if account == nil {
				continue
			}
			authRef := account.FileName
			if authRef == "" {
				authRef = account.ID
			}
			if authRef == ref {
				if account.Provider != "codex" {
					return nil, nil, ErrPoolGuard
				}
				id, count = account.ID, count+1
			}
		}
		if count != 1 || seenIDs[id] {
			return nil, nil, ErrPoolGuard
		}
		seenIDs[id] = true
		ids = append(ids, id)
	}
	return &policy, ids, nil
}

func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

type poolImagesPolicyContextKey struct{}

// withPG03ImagesPolicy binds the verified snapshot to the request context so
// lease admission can enforce the operation without re-reading headers.
func withPG03ImagesPolicy(ctx context.Context, policy *pg03ImagesPolicySnapshot) context.Context {
	if policy == nil {
		return ctx
	}
	return context.WithValue(ctx, poolImagesPolicyContextKey{}, policy)
}

// ImagesOutcomeError carries the durable execution outcome to the Gateway. It
// never reports success for a request whose payload is not persisted.
type ImagesOutcomeError struct {
	Code       string
	Dispatched bool
	ReceiptID  string
	RequestID  string
	AttemptID  string
}

func (e *ImagesOutcomeError) Error() string         { return e.Code }
func (e *ImagesOutcomeError) StatusCode() int       { return http.StatusBadGateway }
func (e *ImagesOutcomeError) IsRequestScoped() bool { return true }
func (e *ImagesOutcomeError) IsRequestStop() bool   { return true }
func (e *ImagesOutcomeError) DirectResponse() bool  { return true }
func (e *ImagesOutcomeError) ResponseBody() []byte {
	body, _ := json.Marshal(map[string]any{"error": map[string]any{
		"message": e.Code, "type": "image_execution_error", "code": e.Code,
		"metadata": map[string]any{
			"request_id": e.RequestID, "attempt_id": e.AttemptID,
			"receipt_id": e.ReceiptID, "images_executor_dispatched": e.Dispatched,
		},
	}})
	return body
}

func (lease *poolLease) imagesOutcomeError(code string) error {
	dispatched := false
	if lease != nil && lease.manager != nil && lease.manager.poolGuard != nil {
		lease.manager.poolGuard.mu.RLock()
		dispatched = lease.Dispatched
		lease.manager.poolGuard.mu.RUnlock()
	}
	return lease.imagesOutcomeErrorWith(code, dispatched)
}

// imagesOutcomeErrorWith is used while poolGuard.mu is already held; it never
// re-enters the guard mutex.
func (lease *poolLease) imagesOutcomeErrorWith(code string, dispatched bool) error {
	requestID, attemptID, receiptID := "", "", ""
	if lease != nil {
		requestID, attemptID, receiptID = lease.receiptRequestID, lease.attemptID, lease.receiptID
	}
	return &ImagesOutcomeError{Code: code, Dispatched: dispatched, ReceiptID: receiptID, RequestID: requestID, AttemptID: attemptID}
}

// ValidateImagesDispatchProtocol inspects the actual outbound request before
// the dispatch fence. The provider call must be the Codex Responses endpoint
// carrying exactly one image_generation tool for the signed model; anything
// else is a request-shaping defect and must not dispatch.
func (lease *poolLease) ValidateImagesDispatchProtocol(req *http.Request) error {
	policy := lease.imagesPolicy
	if policy == nil || req == nil || req.URL == nil || req.Method != http.MethodPost || req.GetBody == nil || strings.HasSuffix(req.URL.Path, "/images/generations") {
		return poolAccountingTermination(ErrPoolGuard, lease)
	}
	if req.Header.Get("Upgrade") != "" || strings.Contains(strings.ToLower(req.Header.Get("Connection")), "upgrade") {
		return poolAccountingTermination(ErrPoolGuard, lease)
	}
	body, err := req.GetBody()
	if err != nil {
		return poolAccountingTermination(ErrPoolGuard, lease)
	}
	defer func() { _ = body.Close() }()
	payload, err := io.ReadAll(io.LimitReader(body, 4*1024*1024))
	if err != nil || !gjson.ValidBytes(payload) {
		return poolAccountingTermination(ErrPoolGuard, lease)
	}
	tools := gjson.GetBytes(payload, "tools")
	if !tools.IsArray() || len(tools.Array()) != 1 {
		return poolAccountingTermination(ErrPoolGuard, lease)
	}
	tool := tools.Array()[0]
	if tool.Get("type").String() != "image_generation" || tool.Get("action").String() != "generate" {
		return poolAccountingTermination(ErrPoolGuard, lease)
	}
	if tool.Get("model").String() != policy.ModelName {
		return poolAccountingTermination(ErrPoolGuard, lease)
	}
	if payload := gjson.GetBytes(payload, "model").String(); payload != policy.BaseModel {
		return poolAccountingTermination(ErrPoolGuard, lease)
	}
	return nil
}

// PersistImagesResult is the only way an images attempt may publish a success
// receipt. The payload is written and synced first; the FINAL receipt follows,
// and a storage failure yields UNKNOWN instead of a success or a replay.
func (lease *poolLease) PersistImagesResult(payload []byte, requested int) error {
	if lease == nil || lease.imagesPolicy == nil {
		return ErrPoolGuard
	}
	guard := lease.manager.poolGuard
	guard.mu.Lock()
	defer guard.mu.Unlock()
	if guard.leases[lease.RequestID] != lease || !lease.Dispatched || lease.receiptFinal || lease.receiptFailed || lease.receiptState != "STARTED" {
		return ErrPoolGuard
	}
	count, format := countImages(payload)
	if count <= 0 {
		return lease.writeImagesFinalLocked(nil, imagesReceiptFinal{
			DispatchState: lease.receiptState, ResultState: "FAILED", RequestedCount: requested,
			ResultCount: 0, BillableImageCount: 0, EndReason: "no_image_output", UsageState: "unavailable",
		})
	}
	billable := min(count, requested)
	meta := imagesReceiptFinal{
		DispatchState: lease.receiptState, ResultState: "COMPLETED", RequestedCount: requested,
		ResultCount: count, BillableImageCount: billable, Partial: count < requested,
		ResponseFormat: format, EndReason: "provider_terminal", UsageState: "unavailable",
	}
	if count > requested {
		meta.EndReason = "over_delivery"
	}
	stored, err := guard.images.save(lease.receiptRequestID, lease.attemptID, payload, meta)
	if err != nil {
		if finalErr := lease.writeImagesFinalLocked(nil, imagesReceiptFinal{
			DispatchState: lease.receiptState, ResultState: "UNKNOWN", RequestedCount: requested,
			ResultCount: count, BillableImageCount: 0, EndReason: "result_storage_failed", UsageState: "unavailable",
		}); finalErr != nil {
			return ErrPoolGuard
		}
		lease.cancel(ErrPoolGuard)
		return lease.imagesOutcomeErrorWith("image_result_storage_failed", true)
	}
	return lease.writeImagesFinalLocked(nil, stored)
}

// writeImagesFinalLocked persists the schema-3 FINAL receipt. A failed write
// marks the lease unknown: the caller may not return a success payload.
func (lease *poolLease) writeImagesFinalLocked(_ []byte, result imagesReceiptFinal) error {
	w := lease.manager.poolGuard.receipts
	if w == nil {
		return ErrPoolGuard
	}
	state := lease.receiptState
	sequence := 2
	if state == "STARTED" {
		sequence = 3
	}
	if state == "NOT_STARTED" && result.ResultState == "FAILED" {
		sequence = 2
	}
	event := w.event(lease, "FINAL", state, sequence)
	event.Images = &result
	if err := w.write(event); err != nil {
		logEntryWithRequestID(lease.ctx).Warnf("images FINAL receipt write failed: %v", err)
		lease.receiptFailed = true
		lease.cancel(ErrPoolGuard)
		return ErrPoolGuard
	}
	lease.receiptFinal = true
	lease.imagesFinalEvent = event
	if event.Images.ResultState == "FAILED" {
		return lease.imagesOutcomeErrorWith("image_no_output", lease.Dispatched)
	}
	if event.Images.ResultState != "COMPLETED" {
		return lease.imagesOutcomeErrorWith("image_outcome_unknown", lease.Dispatched)
	}
	return nil
}

// finalizeImagesExecution writes an UNKNOWN FINAL when the provider call ended
// without a persisted result. It never fabricates success.
func (lease *poolLease) finalizeImagesExecution(defaultState string) {
	guard := lease.manager.poolGuard
	guard.mu.Lock()
	defer guard.mu.Unlock()
	if guard.receipts == nil || lease.receiptFinal {
		return
	}
	result := imagesReceiptFinal{DispatchState: lease.receiptState, ResultState: "UNKNOWN", RequestedCount: 1, EndReason: defaultState, UsageState: "unavailable"}
	if lease.receiptState == "NOT_STARTED" {
		result.ResultState = "FAILED"
		result.EndReason = "not_dispatched"
	}
	if err := lease.writeImagesFinalLocked(nil, result); err != nil {
		lease.receiptFailed = true
	}
}

// ImagesExecutionRecord is the read-only projection returned to the Gateway.
type ImagesExecutionRecord struct {
	Schema        int                 `json:"schema"`
	RequestID     string              `json:"request_id"`
	AttemptID     string              `json:"attempt_id"`
	ReceiptID     string              `json:"receipt_id,omitempty"`
	State         string              `json:"state"`
	ResultState   string              `json:"result_state,omitempty"`
	ResultRef     string              `json:"result_ref,omitempty"`
	ResultSHA256  string              `json:"result_sha256,omitempty"`
	ResultBytes   int64               `json:"result_bytes,omitempty"`
	ResultCount   int                 `json:"result_count"`
	BillableCount int                 `json:"billable_image_count"`
	Requested     int                 `json:"requested_count"`
	EndReason     string              `json:"end_reason,omitempty"`
	Events        []map[string]any    `json:"events"`
	Meta          *imagesReceiptFinal `json:"meta,omitempty"`
	Usage         map[string]any      `json:"usage,omitempty"`
	Final         map[string]any      `json:"final,omitempty"`
	Found         bool                `json:"found"`
}

// QueryImagesExecution reads the durable receipt for one request/attempt. It
// answers "did this attempt exist, and what was its trusted outcome" without
// mutating any state, so a Gateway restart can resolve UNKNOWN safely.
//
// An attempt with no receipt returns a populated record with Found=false and
// no error: that is the trusted zero-dispatch proof the Gateway needs before it
// may hand over to another source. A broken receipt store still returns an
// error, so a storage fault can never masquerade as "nothing was sent".
func (m *Manager) QueryImagesExecution(requestID, attemptID string) (ImagesExecutionRecord, error) {
	record := ImagesExecutionRecord{Schema: 3, RequestID: requestID, AttemptID: attemptID}
	if m == nil || m.poolGuard == nil || m.poolGuard.receipts == nil {
		return record, ErrPoolGuard
	}
	if !validReceiptID(requestID) || !validReceiptID(attemptID) {
		return record, ErrPoolGuard
	}
	events, err := m.poolGuard.receipts.readAttempt(requestID, attemptID)
	if err != nil {
		if errors.Is(err, ErrPoolReceiptNotFound) {
			return record, nil
		}
		return record, err
	}
	record.Events = events
	for _, event := range events {
		state, _ := event["state"].(string)
		if state != "" {
			record.State = state
		}
		receiptID, _ := event["receipt_id"].(string)
		if _, ok := event["receipt_id"]; ok {
			record.ReceiptID = receiptID
		}
		if raw, ok := event["images"].(map[string]any); ok {
			record.ResultState, _ = raw["result_state"].(string)
			record.ResultRef, _ = raw["result_ref"].(string)
			record.ResultSHA256, _ = raw["result_sha256"].(string)
			record.EndReason, _ = raw["end_reason"].(string)
			record.ResultCount = intFromAny(raw["result_count"])
			record.BillableCount = intFromAny(raw["billable_image_count"])
			record.Requested = intFromAny(raw["requested_count"])
			record.ResultBytes = int64FromAny(raw["result_bytes"])
			record.Final = event
		}
	}
	record.Found = len(events) > 0
	if record.Found && record.ResultSHA256 != "" && m.poolGuard.images != nil {
		if _, meta, err := m.poolGuard.images.load(requestID, attemptID); err == nil {
			record.Meta = &meta
		}
	}
	return record, nil
}

// LoadImagesResult returns the persisted payload only when its metadata and
// digest still match; a mismatch is a review condition, never a success.
func (m *Manager) LoadImagesResult(requestID, attemptID string) ([]byte, imagesReceiptFinal, error) {
	if m == nil || m.poolGuard == nil || m.poolGuard.images == nil {
		return nil, imagesReceiptFinal{}, ErrPoolGuard
	}
	if !validReceiptID(requestID) || !validReceiptID(attemptID) {
		return nil, imagesReceiptFinal{}, ErrPoolGuard
	}
	return m.poolGuard.images.load(requestID, attemptID)
}

func intFromAny(value any) int {
	switch v := value.(type) {
	case float64:
		return int(v)
	case int:
		return v
	case json.Number:
		n, _ := v.Int64()
		return int(n)
	}
	return 0
}

func int64FromAny(value any) int64 {
	switch v := value.(type) {
	case float64:
		return int64(v)
	case int64:
		return v
	case json.Number:
		n, _ := v.Int64()
		return n
	}
	return 0
}

// poolImagesCapabilities is the operation-level capability requirement. The
// grant floor (text_chat, exact_usage) still applies on top of it; image
// generation never widens or replaces that floor.
func poolImagesCapabilities() []string { return []string{ImagePoolCapability} }

// poolImagesAdmitted enforces the account×model×base-model admission for one
// images request: the operator grant must name both the image model and the
// base model, and the capability ledger must hold a verified record for both,
// bound to the same credential digest and trust generation.
func (m *Manager) poolImagesAdmitted(record *PoolGrantFile, auth *Auth, policy *pg03ImagesPolicySnapshot, model string) error {
	if policy == nil {
		return ErrPoolGuard
	}
	grant, reason, err := m.matchPoolGrantReason(record, auth, model, poolImagesCapabilities())
	if err != nil {
		poolLogModelDecision(context.Background(), auth, model, model, false, reason, record.Revision, 0)
		return ErrPoolGuard
	}
	for _, candidate := range []string{model, policy.BaseModel} {
		if !containsString(grant.Models, candidate) {
			return ErrPoolGuard
		}
	}
	for _, candidate := range []string{model, policy.BaseModel} {
		if reason, err := m.poolModelAdmitted(record, auth, candidate); err != nil {
			poolLogModelDecision(context.Background(), auth, model, candidate, false, reason, record.Revision, 0)
			return ErrPoolGuard
		}
	}
	return nil
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

// imagesResultStore persists the exact image payload and a small metadata
// record. Both paths are deterministic per request/attempt so a restart or a
// duplicate receipt resolves to the same bytes and digest.
type imagesResultStore struct{ dir string }

func newImagesResultStore() (*imagesResultStore, error) {
	dir := strings.TrimSpace(os.Getenv(imagesResultDirEnv))
	if dir == "" {
		return nil, nil
	}
	if !imagesModeEnabled() {
		return nil, errors.New("images result storage requires CLEARAPI_PG03_IMAGES=true")
	}
	handle, err := openReceiptDirectory(dir)
	if err != nil {
		return nil, err
	}
	if err := handle.Close(); err != nil {
		return nil, err
	}
	return &imagesResultStore{dir: dir}, nil
}

func imagesResultKey(requestID, attemptID string) string {
	sum := sha256.Sum256([]byte(requestID + "\n" + attemptID))
	return hex.EncodeToString(sum[:])
}

// save writes the payload first and its metadata second. A caller must not
// publish a success receipt unless both writes and the sync succeed.
func (store *imagesResultStore) save(requestID, attemptID string, payload []byte, meta imagesReceiptFinal) (imagesReceiptFinal, error) {
	if store == nil {
		return meta, ErrPoolGuard
	}
	if len(payload) == 0 || len(payload) > 32*1024*1024 {
		return meta, ErrPoolGuard
	}
	key := imagesResultKey(requestID, attemptID)
	digest := sha256.Sum256(payload)
	meta.ResultRef = "imgresult_" + key
	meta.ResultSHA256 = hex.EncodeToString(digest[:])
	meta.ResultBytes = int64(len(payload))
	directory, err := openReceiptDirectory(store.dir)
	if err != nil {
		return meta, err
	}
	defer func() { _ = directory.Close() }()
	if err := writeImagesArtifact(directory, store.dir, meta.ResultRef+".json", payload); err != nil {
		return meta, err
	}
	encoded, err := json.Marshal(meta)
	if err != nil {
		return meta, err
	}
	if err := writeImagesArtifact(directory, store.dir, meta.ResultRef+".meta.json", encoded); err != nil {
		return meta, err
	}
	if err := directory.Sync(); err != nil {
		return meta, err
	}
	return meta, nil
}

// writeImagesArtifact creates the artifact once and syncs it. A replay of the
// same attempt must resolve to the identical bytes; any divergence is a
// conflict, never a silent overwrite.
func writeImagesArtifact(directory *os.File, dir, name string, payload []byte) error {
	file, err := openReceiptFile(directory, name, true)
	if err == nil {
		written, writeErr := file.Write(payload)
		syncErr := file.Sync()
		closeErr := file.Close()
		if writeErr != nil || written != len(payload) || syncErr != nil || closeErr != nil {
			return ErrPoolGuard
		}
		return nil
	}
	existing, readErr := os.ReadFile(filepath.Join(dir, name))
	if readErr != nil || !equalBytes(existing, payload) {
		return ErrPoolGuard
	}
	return nil
}

func (store *imagesResultStore) load(requestID, attemptID string) ([]byte, imagesReceiptFinal, error) {
	if store == nil {
		return nil, imagesReceiptFinal{}, ErrPoolGuard
	}
	key := imagesResultKey(requestID, attemptID)
	metaRaw, err := os.ReadFile(filepath.Join(store.dir, "imgresult_"+key+".meta.json"))
	if err != nil {
		return nil, imagesReceiptFinal{}, ErrPoolGuard
	}
	var meta imagesReceiptFinal
	if json.Unmarshal(metaRaw, &meta) != nil || meta.ResultRef != "imgresult_"+key {
		return nil, imagesReceiptFinal{}, ErrPoolGuard
	}
	payload, err := os.ReadFile(filepath.Join(store.dir, meta.ResultRef+".json"))
	if err != nil {
		return nil, imagesReceiptFinal{}, ErrPoolGuard
	}
	digest := sha256.Sum256(payload)
	if hex.EncodeToString(digest[:]) != meta.ResultSHA256 || int64(len(payload)) != meta.ResultBytes {
		return nil, imagesReceiptFinal{}, ErrPoolGuard
	}
	return payload, meta, nil
}

// countImages applies the OpenAI image payload rule: an object payload is one
// image when it carries url or b64_json; an array counts max(url entries,
// b64_json entries). Entry counts alone are never billing evidence.
func countImages(payload []byte) (count int, format string) {
	data := gjson.GetBytes(payload, "data")
	hasField := func(item gjson.Result, field string) bool {
		value := item.Get(field)
		return value.Type == gjson.String && value.Raw != `""`
	}
	if data.IsObject() {
		if hasField(data, "url") || hasField(data, "b64_json") {
			count = 1
		}
	} else if data.IsArray() {
		var urls, b64s int
		data.ForEach(func(_, item gjson.Result) bool {
			if hasField(item, "url") {
				urls++
			}
			if hasField(item, "b64_json") {
				b64s++
			}
			return true
		})
		count = urls
		if b64s > count {
			count = b64s
		}
	}
	switch {
	case gjson.GetBytes(payload, "data.0.url").Exists():
		format = "url"
	case gjson.GetBytes(payload, "data.0.b64_json").Exists():
		format = "b64_json"
	}
	return count, format
}

// imagesResultPathEnv is exported through the management query so operators
// can correlate a receipt with the stored payload without reading it.
func imagesResultDir() string { return strings.TrimSpace(os.Getenv(imagesResultDirEnv)) }

// uintToString is used by the deterministic attempt metadata.
func uintToString(value uint64) string { return strconv.FormatUint(value, 10) }
