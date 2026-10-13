package auth

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	internalconfig "github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	internallogging "github.com/router-for-me/CLIProxyAPI/v8/internal/logging"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/usage"
)

const PoolGuardVersion = 3

type poolAdmissionError struct{}

func (poolAdmissionError) Error() string         { return "pool account admission required" }
func (poolAdmissionError) StatusCode() int       { return http.StatusForbidden }
func (poolAdmissionError) IsRequestScoped() bool { return true }
func (poolAdmissionError) IsRequestStop() bool   { return true }

func (poolAdmissionError) DirectResponse() bool { return true }
func (poolAdmissionError) ResponseBody() []byte {
	return []byte(`{"error":{"message":"pool account admission required","type":"security_error","code":"pool_admission_required"}}`)
}

var ErrPoolGuard = poolAdmissionError{}

type poolAttemptContextKey struct{}
type atomicPoolAttempt = atomic.Bool

func (m *Manager) poolExecutionContext(ctx context.Context) (context.Context, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if m.poolGuard == nil {
		return ctx, nil
	}
	if m.poolGuard.role != "service" || m.HomeEnabled() || m.hasPluginScheduler() {
		return ctx, ErrPoolGuard
	}
	return context.WithValue(ctx, poolAttemptContextKey{}, &atomic.Bool{}), nil
}

// Pool grants are a separate operator-owned control file, never auth metadata
// or client request metadata. The file must be mounted outside the auth store.
// No grant is shipped or generated automatically by this implementation.
type PoolGrant struct {
	AuthID string `json:"auth_id"`
	// Provider and CredentialDigest must match the canonical credential
	// security identity (sdk/cliproxy/auth PoolCredentialDigest,
	// CredentialSecurityIdentityVersion) of the granted credential.
	Provider         string   `json:"provider"`
	CredentialDigest string   `json:"credential_digest"`
	Models           []string `json:"models"`
	Capabilities     []string `json:"capabilities"`
	NativeTools      bool     `json:"native_tools"`
	SourceEvidence   []string `json:"source_evidence"`
	TestEvidence     []string `json:"test_evidence"`
	Enabled          bool     `json:"enabled"`
	ExpiresAt        int64    `json:"expires_at"`
	MaxConcurrency   int      `json:"max_concurrency"`
}

type PoolGrantFile struct {
	GuardVersion int                   `json:"guard_version"`
	ExecutorID   string                `json:"executor_id"`
	Revision     uint64                `json:"revision"`
	Grants       []PoolGrant           `json:"grants"`
	Capabilities []PoolModelCapability `json:"capabilities,omitempty"`
}

type poolGuard struct {
	role         string
	file         string
	executorID   string
	checkpoint   string
	journalMu    sync.Mutex
	mu           sync.RWMutex
	countsMu     sync.Mutex
	counts       map[string]int
	lastRevision uint64
	lastDigest   string
	trust        map[string]PoolTrustRecord
	leases       map[uint64]*poolLease
	nextLease    uint64
	faulted      atomic.Bool
	now          func() time.Time
	receipts     *receiptWriter
	receiptErr   error
}

func newPoolGuard() *poolGuard {
	role := strings.TrimSpace(os.Getenv("CLEARAPI_POOL_ROLE"))
	if role == "" {
		return nil
	}
	receipts, receiptErr := newReceiptWriter()
	return &poolGuard{role: role, file: os.Getenv("CLEARAPI_POOL_ADMISSION_FILE"), executorID: strings.TrimSpace(os.Getenv("CLEARAPI_POOL_EXECUTOR_ID")), checkpoint: os.Getenv("CLEARAPI_POOL_CHECKPOINT_FILE"), counts: make(map[string]int), receipts: receipts, receiptErr: receiptErr}
}

func (m *Manager) PoolRole() string {
	if m == nil || m.poolGuard == nil {
		return ""
	}
	return m.poolGuard.role
}

func (guard *poolGuard) grants() (*PoolGrantFile, error) {
	if guard == nil || guard.role != "service" || guard.file == "" {
		return nil, ErrPoolGuard
	}
	info, err := os.Lstat(guard.file)
	if err != nil || !info.Mode().IsRegular() || info.Size() > 1024*1024 {
		return nil, ErrPoolGuard
	}
	file, err := os.Open(guard.file)
	if err != nil {
		return nil, ErrPoolGuard
	}
	defer file.Close()
	var record PoolGrantFile
	decoder := json.NewDecoder(io.LimitReader(file, 1024*1024+1))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&record) != nil || record.GuardVersion != PoolGuardVersion || record.ExecutorID != guard.executorID || !validPoolExecutorID(guard.executorID) || record.Revision < 1 || len(record.Grants) > 1024 || !validPoolCapabilities(&record) {
		return nil, ErrPoolGuard
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return nil, ErrPoolGuard
	}
	return &record, nil
}

func (m *Manager) poolGrants() (*PoolGrantFile, error) {
	return m.loadPoolGrants(false)
}

func (m *Manager) loadPoolGrants(readOnly bool) (*PoolGrantFile, error) {
	guard := m.poolGuard
	if guard == nil || guard.role != "service" || guard.checkpoint == "" || guard.faulted.Load() {
		return nil, ErrPoolGuard
	}
	cfg, _ := m.runtimeConfig.Load().(*internalconfig.Config)
	if cfg == nil || cfg.AuthDir == "" {
		return nil, ErrPoolGuard
	}
	root, err := filepath.Abs(cfg.AuthDir)
	if err == nil {
		root, err = filepath.EvalSymlinks(root)
	}
	if err != nil {
		return nil, ErrPoolGuard
	}
	if runtime.GOOS == "windows" {
		root = strings.ToLower(root)
	}
	paths := make([]string, 0, 2)
	for _, path := range []string{guard.file, guard.checkpoint} {
		absolute, err := filepath.Abs(path)
		if err != nil {
			return nil, ErrPoolGuard
		}
		resolved, err := filepath.EvalSymlinks(absolute)
		if runtime.GOOS == "windows" {
			resolved = strings.ToLower(resolved)
		}
		if err != nil || resolved == root || strings.HasPrefix(resolved, root+string(os.PathSeparator)) {
			return nil, ErrPoolGuard
		}
		paths = append(paths, resolved)
	}
	if paths[0] == paths[1] {
		return nil, ErrPoolGuard
	}
	record, err := guard.grants()
	if err != nil {
		return nil, err
	}
	if readOnly {
		// Preflight never advances or synchronizes the journal. A pending
		// policy refresh fails closed until normal runtime has accepted it.
		guard.journalMu.Lock()
		defer guard.journalMu.Unlock()
		info, err := os.Lstat(guard.checkpoint)
		if err != nil || !info.Mode().IsRegular() {
			return nil, ErrPoolGuard
		}
		file, err := os.Open(guard.checkpoint)
		if err != nil {
			return nil, ErrPoolGuard
		}
		defer file.Close()
		floor, _, err := guard.readPoolCheckpoint(file)
		if err != nil || record.Revision != floor.Revision || poolRecordDigest(record) != floor.Digest || floor.Revision != guard.lastRevision || floor.Digest != guard.lastDigest {
			return nil, ErrPoolGuard
		}
	} else {
		if err := guard.acceptCheckpoint(record); err != nil {
			return nil, err
		}
	}
	return record, nil
}

func (m *Manager) poolGrant(auth *Auth, model string, capabilities []string) (*PoolGrant, error) {
	guard := m.poolGuard
	if guard == nil {
		return nil, nil
	}
	if guard.role != "service" || auth == nil || auth.AuthKind() != AuthKindOAuth || auth.Disabled || ManagementIsolation(auth) || auth.Status == StatusDisabled || auth.Unavailable {
		return nil, ErrPoolGuard
	}
	record, err := m.poolGrants()
	if err != nil {
		return nil, err
	}
	if _, ok := guard.trusted(auth, record.Revision); !ok {
		return nil, ErrPoolGuard
	}
	return m.matchPoolGrant(record, auth, model, capabilities)
}

func (m *Manager) matchPoolGrant(record *PoolGrantFile, auth *Auth, model string, capabilities []string) (*PoolGrant, error) {
	grant, _, err := m.matchPoolGrantReason(record, auth, model, capabilities)
	return grant, err
}

// matchPoolGrantReason validates the operator grant floor and returns a
// structured denial reason for observability on failure.
func (m *Manager) matchPoolGrantReason(record *PoolGrantFile, auth *Auth, model string, capabilities []string) (*PoolGrant, string, error) {
	const structural = "grant_invalid"
	digest := PoolCredentialDigest(auth)
	now := time.Now().Unix()
	if m.poolGuard.now != nil {
		now = m.poolGuard.now().Unix()
	}
	var match *PoolGrant
	for i := range record.Grants {
		grant := &record.Grants[i]
		if grant.AuthID != auth.ID {
			continue
		}
		if match != nil {
			return nil, structural, ErrPoolGuard
		}
		match = grant
	}
	if match == nil || !match.Enabled || match.Provider != auth.Provider || digest == "" || match.CredentialDigest != digest || match.ExpiresAt <= now || match.ExpiresAt > now+1800 || match.MaxConcurrency < 1 || match.MaxConcurrency > 64 || len(match.SourceEvidence) == 0 || len(match.TestEvidence) == 0 {
		return nil, structural, ErrPoolGuard
	}
	if !slices.Contains(match.Models, model) {
		return nil, PoolDenialModelNotAllowed, ErrPoolGuard
	}
	for _, reference := range append(slices.Clone(match.SourceEvidence), match.TestEvidence...) {
		if strings.TrimSpace(reference) == "" {
			return nil, structural, ErrPoolGuard
		}
	}
	for _, capability := range append([]string{"text_chat", "exact_usage"}, capabilities...) {
		if !slices.Contains(match.Capabilities, capability) {
			return nil, structural, ErrPoolGuard
		}
		if capability == "tools" && !match.NativeTools {
			return nil, structural, ErrPoolGuard
		}
	}
	return match, "", nil
}

func poolRequestCapabilities(req cliproxyexecutor.Request, stream bool) ([]string, error) {
	caps := []string{}
	if stream {
		caps = append(caps, "stream_text")
	}
	if len(req.Payload) > 64*1024 {
		caps = append(caps, "long_context")
	}
	if len(req.Payload) == 0 {
		return caps, nil
	}
	var body any
	if json.Unmarshal(req.Payload, &body) != nil {
		return nil, ErrPoolGuard
	}
	var inspect func(any)
	inspect = func(value any) {
		switch value := value.(type) {
		case map[string]any:
			for key, child := range value {
				if (key == "type" && (child == "tool_use" || child == "tool_result" || child == "function_call" || child == "function_call_output")) || (key == "role" && (child == "tool" || child == "function")) {
					caps = append(caps, "tools")
				}
				switch key {
				case "tools", "functions", "tool_calls", "function_call", "tool_use", "tool_result", "functionDeclarations", "function_declarations", "functionResponse", "function_response", "allowedFunctionNames", "allowed_function_names":
					// Empty declarations carry no executable tools. Unknown nonempty
					// shapes remain tools-bearing rather than bypassing admission.
					if child != nil && !(key == "function_call" && (child == "none" || child == "auto")) {
						if declarations, ok := child.([]any); !ok || len(declarations) != 0 {
							caps = append(caps, "tools")
						}
					}
				case "tool_choice", "functionCall":
					if child != nil && child != "none" && child != "auto" {
						caps = append(caps, "tools")
					}
				case "functionCallingConfig", "function_calling_config":
					if config, ok := child.(map[string]any); ok && config["mode"] == "ANY" {
						caps = append(caps, "tools")
					}
				}
				if key == "image_url" || key == "inlineData" || key == "inline_data" {
					caps = append(caps, "image_input")
				}
				if key == "type" && (child == "input_image" || child == "image") {
					caps = append(caps, "image_input")
				}
				inspect(child)
			}
		case []any:
			for _, child := range value {
				inspect(child)
			}
		}
	}
	inspect(body)
	return caps, nil
}

type poolExecutor struct {
	ProviderExecutor
	manager *Manager
}

// Forward session cleanup, but do not permit implicit credential preparation:
// credentials must be prepared in staging and explicitly promoted again.
func (executor *poolExecutor) CloseExecutionSession(sessionID string) {
	if closer, ok := executor.ProviderExecutor.(ExecutionSessionCloser); ok {
		closer.CloseExecutionSession(sessionID)
	}
}

func (executor *poolExecutor) ShouldPrepareRequestAuth(auth *Auth) bool {
	preparer, ok := executor.ProviderExecutor.(RequestAuthPreparer)
	return ok && preparer.ShouldPrepareRequestAuth(auth)
}

func (executor *poolExecutor) PrepareRequestAuth(context.Context, *Auth) (*Auth, error) {
	return nil, ErrPoolGuard
}

func (executor *poolExecutor) PrepareRequest(*http.Request, *Auth) error {
	return ErrPoolGuard
}

func (executor *poolExecutor) begin(ctx context.Context, auth *Auth, req cliproxyexecutor.Request, opts cliproxyexecutor.Options, stream bool, consumeAttempt bool) (*poolLease, error) {
	guard := executor.manager.poolGuard
	if guard.receiptErr != nil {
		return nil, ErrPoolGuard
	}
	if !poolProtocolAdmitted(ctx, opts, stream) {
		return nil, ErrPoolGuard
	}
	if stream && guard.receipts == nil {
		return nil, ErrPoolGuard
	}
	if guard.receipts != nil && (guard.receipts.faulted.Load() || !consumeAttempt) {
		return nil, ErrPoolGuard
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if consumeAttempt {
		budget, _ := ctx.Value(poolAttemptContextKey{}).(*atomicPoolAttempt)
		if budget == nil || budget.Load() {
			return nil, ErrPoolGuard
		}
	}
	guard.mu.Lock()
	defer guard.mu.Unlock()
	if auth == nil || auth.Provider != "codex" || auth.AuthKind() != AuthKindOAuth {
		return nil, ErrPoolGuard
	}
	// Unsupported executors cannot claim a dispatch fence merely by registration.
	fenced, ok := executor.ProviderExecutor.(interface{ PoolDispatchFencing() bool })
	if !ok || !fenced.PoolDispatchFencing() {
		return nil, ErrPoolGuard
	}
	executor.manager.mu.RLock()
	current := executor.manager.auths[auth.ID]
	currentMatches := current != nil && !current.Disabled && !ManagementIsolation(current) && current.Status != StatusDisabled && !current.Unavailable && PoolCredentialDigest(current) == PoolCredentialDigest(auth)
	executor.manager.mu.RUnlock()
	if !currentMatches {
		return nil, ErrPoolGuard
	}
	caps, err := poolRequestCapabilities(req, stream)
	if err != nil {
		return nil, err
	}
	record, err := executor.manager.poolGrants()
	if err != nil {
		return nil, err
	}
	grant, reason, err := executor.manager.matchPoolGrantReason(record, auth, req.Model, caps)
	if err != nil {
		poolLogModelDecision(ctx, auth, requestedModelFromOptions(opts), req.Model, false, reason, record.Revision, 0)
		return nil, err
	}
	reason, admitErr := executor.manager.poolModelAdmitted(record, auth, req.Model)
	if admitErr != nil {
		poolLogModelDecision(ctx, auth, requestedModelFromOptions(opts), req.Model, false, reason, record.Revision, 0)
		return nil, admitErr
	}
	guard.journalMu.Lock()
	trust := guard.trust[auth.ID]
	guard.journalMu.Unlock()
	if trust.State != PoolTrustTrusted || trust.AuthorizationVersion != record.Revision {
		return nil, ErrPoolGuard
	}
	if stream && guard.receipts != nil {
		id := poolCapacityReceiptID(opts.Headers.Get("X-ClearAPI-PG02-Request"), opts.Headers.Get("X-ClearAPI-PG02-Attempt"))
		if exists, err := guard.receipts.receiptExists(id); err != nil || exists {
			return nil, ErrPoolGuard
		}
	}
	guard.countsMu.Lock()
	defer guard.countsMu.Unlock()
	if guard.counts[auth.ID] >= grant.MaxConcurrency {
		if stream && consumeAttempt {
			return nil, executor.capacityRejection(ctx, auth, req, opts, trust, record)
		}
		return nil, ErrPoolGuard
	}
	poolLogModelDecision(ctx, auth, requestedModelFromOptions(opts), req.Model, true, "", record.Revision, trust.Generation)
	if ctx == nil {
		ctx = context.Background()
	}
	if cause := context.Cause(ctx); cause != nil {
		return nil, cause
	}
	parent := ctx
	persistent := stream && cliproxyexecutor.DownstreamWebsocket(ctx) && poolExecutionSessionID(opts) != ""
	if persistent {
		// The request context owns the active turn; the retained lifecycle owns
		// the idle socket. Keep values (including the one-shot attempt budget).
		parent = context.WithoutCancel(ctx)
	}
	child, cancel := context.WithCancelCause(parent)
	guard.nextLease++
	attemptID := ""
	receiptRequestID := ""
	if guard.receipts != nil && opts.Headers != nil {
		attemptID = strings.TrimSpace(opts.Headers.Get("X-ClearAPI-PG02-Attempt"))
		receiptRequestID = strings.TrimSpace(opts.Headers.Get("X-ClearAPI-PG02-Request"))
	}
	if receiptRequestID == "" {
		receiptRequestID = internallogging.GetRequestID(ctx)
	}
	if !validReceiptID(receiptRequestID) {
		receiptRequestID = "pool-" + strconv.FormatUint(guard.nextLease, 10)
	}
	if guard.receipts != nil && attemptID != "" && !validReceiptID(attemptID) {
		cancel(ErrPoolGuard)
		return nil, ErrPoolGuard
	}
	if stream && (!validReceiptID(attemptID) || !validReceiptID(receiptRequestID)) {
		cancel(ErrPoolGuard)
		return nil, ErrPoolGuard
	}
	lease := &poolLease{PoolInFlight: PoolInFlight{RequestID: guard.nextLease, AuthID: auth.ID, Provider: auth.Provider, ExecutorID: guard.executorID, CredentialDigest: PoolCredentialDigest(auth), AuthorizationVersion: trust.AuthorizationVersion, Generation: trust.Generation}, manager: executor.manager, auth: auth.Clone(), req: req, caps: caps, requestedModel: requestedModelFromOptions(opts), attemptID: attemptID, sessionID: poolExecutionSessionID(opts), ctx: child, cancel: cancel, consumeAttempt: consumeAttempt, persistent: persistent, receiptID: uuid.NewString(), receiptState: "NOT_STARTED", receiptRequestID: receiptRequestID}
	lease.ctx = usage.WithCodexMeteringObserver(cliproxyexecutor.WithDispatchGuard(child, lease), lease.observeMetering)
	// Keep private admission evidence independent of provider mutations.
	admission := opts
	admission.OriginalRequest = append([]byte(nil), opts.OriginalRequest...)
	admission.Headers = opts.Headers.Clone()
	admission.Metadata = map[string]any{cliproxyexecutor.RequestPathMetadataKey: opts.Metadata[cliproxyexecutor.RequestPathMetadataKey]}
	lease.protocolAdmitted = func() bool { return poolProtocolAdmitted(ctx, admission, stream) }
	lease.receiptSSE = stream
	if stream {
		if proof, ok := ctx.Value(poolSSEFallbackContextKey{}).(*poolSSEZeroDispatchError); ok {
			accountRef := sha256.Sum256([]byte(auth.ID))
			if proof.final.RequestID != receiptRequestID || proof.final.AttemptID != attemptID || proof.final.CanonicalModel != req.Model || proof.final.AccountRef == hex.EncodeToString(accountRef[:]) {
				cancel(ErrPoolGuard)
				return nil, ErrPoolGuard
			}
			verifyParent := func() error { return guard.receipts.verifyZeroDispatchParent(proof.final) }
			if chain, ok := ctx.Value(poolSSEFallbackChainContextKey{}).(*poolSSEFallbackChain); ok && auth.Provider == "codex" {
				verifyParent = func() error {
					if chain.count() == 0 || chain.count() >= maxPG03SSEFallbackAccounts || chain.proofs[chain.count()-1] != proof {
						return ErrPoolGuard
					}
					return guard.receipts.verifyZeroDispatchChain(chain.proofs[:chain.count()-1], proof.final)
				}
			}
			if err := verifyParent(); err != nil {
				cancel(ErrPoolGuard)
				return nil, ErrPoolGuard
			}
			lease.previousReceiptID = proof.final.ReceiptID
		}
		// Durable identity prevents replay across process restarts. B still
		// shares the one-shot dispatch budget, with its own account receipt.
		digest := sha256.Sum256([]byte(receiptRequestID + "\n" + attemptID + "\n" + auth.ID))
		lease.receiptID = hex.EncodeToString(digest[:])
	}
	if guard.receipts != nil {
		if err := guard.receipts.begin(lease); err != nil {
			cancel(ErrPoolGuard)
			return nil, ErrPoolGuard
		}
	}
	lease.stopClose = context.AfterFunc(child, lease.closeResource)
	if guard.leases == nil {
		guard.leases = make(map[uint64]*poolLease)
	}
	guard.leases[lease.RequestID] = lease
	guard.counts[auth.ID]++
	return lease, nil
}

func poolExecutionSessionID(opts cliproxyexecutor.Options) string {
	if opts.Metadata == nil {
		return ""
	}
	value, _ := opts.Metadata[cliproxyexecutor.ExecutionSessionMetadataKey].(string)
	return strings.TrimSpace(value)
}
func (executor *poolExecutor) Execute(ctx context.Context, auth *Auth, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
	lease, err := executor.begin(ctx, auth, req, opts, false, true)
	if err != nil {
		return cliproxyexecutor.Response{}, poolAccountingTermination(err, nil)
	}
	defer lease.End("completed")
	opts.ExecutionLifecycle = lease
	response, err := executor.ProviderExecutor.Execute(lease.ctx, auth, req, opts)
	if cause := context.Cause(lease.ctx); cause != nil {
		return cliproxyexecutor.Response{}, poolAccountingTermination(cause, lease)
	}
	return response, err
}

func (executor *poolExecutor) ExecuteStream(ctx context.Context, auth *Auth, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) (result *cliproxyexecutor.StreamResult, resultErr error) {
	lease, err := executor.begin(ctx, auth, req, opts, true, true)
	if err != nil {
		return nil, poolAccountingTermination(err, nil)
	}
	handedOff := false
	defer func() {
		if !handedOff {
			lease.End("bootstrap_end")
		}
	}()
	opts.ExecutionLifecycle = lease
	result, err = executor.ProviderExecutor.ExecuteStream(lease.ctx, auth, req, opts)
	if cause := context.Cause(lease.ctx); cause != nil {
		return nil, poolAccountingTermination(cause, lease)
	}
	if err != nil || result == nil || result.Chunks == nil {
		return result, err
	}
	upstream := result
	chunks := make(chan cliproxyexecutor.StreamChunk, 1)
	go func() {
		defer close(chunks)
		defer lease.End("stream_end")
		terminate := func() {
			// Discard an undelivered buffered payload, preserving the explicit terminal.
			select {
			case <-chunks:
			default:
			}
			if cause := context.Cause(lease.ctx); cause != nil && cause != context.Canceled {
				chunks <- cliproxyexecutor.StreamChunk{Err: poolAccountingTermination(cause, lease)}
			}
		}
		for {
			if lease.ctx.Err() != nil {
				terminate()
				return
			}
			select {
			case <-lease.ctx.Done():
				terminate()
				return
			case chunk, ok := <-upstream.Chunks:
				if !ok {
					if lease.ctx.Err() != nil {
						terminate()
					}
					return
				}
				if lease.ctx.Err() != nil {
					terminate()
					return
				}
				select {
				case chunks <- chunk:
					if chunk.Err != nil {
						return
					}
				case <-lease.ctx.Done():
					terminate()
					return
				}
			}
		}
	}()
	handedOff = true
	if lease.receiptSSE {
		if upstream.Headers == nil {
			upstream.Headers = make(http.Header)
		}
		upstream.Headers.Set("X-ClearAPI-PG02-Receipt", lease.receiptID)
	}
	return &cliproxyexecutor.StreamResult{Headers: upstream.Headers, Chunks: chunks}, nil
}

func (executor *poolExecutor) CountTokens(ctx context.Context, auth *Auth, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
	lease, err := executor.begin(ctx, auth, req, opts, false, true)
	if err != nil {
		return cliproxyexecutor.Response{}, poolAccountingTermination(err, nil)
	}
	defer lease.End("count_end")
	response, err := executor.ProviderExecutor.CountTokens(lease.ctx, auth, req, opts)
	if cause := context.Cause(lease.ctx); cause != nil {
		return cliproxyexecutor.Response{}, poolAccountingTermination(cause, lease)
	}
	return response, err
}

func (executor *poolExecutor) HttpRequest(context.Context, *Auth, *http.Request) (*http.Response, error) {
	return nil, ErrPoolGuard
}

// Service refresh cannot mint a new identity outside explicit staging/promotion.
func (executor *poolExecutor) Refresh(context.Context, *Auth) (*Auth, error) {
	return nil, ErrPoolGuard
}

func quarantinePoolAuth(auth *Auth) {
	auth.Disabled, auth.Status = true, StatusDisabled
	if auth.Metadata == nil {
		auth.Metadata = make(map[string]any)
	}
	auth.Metadata["disabled"] = true
}
