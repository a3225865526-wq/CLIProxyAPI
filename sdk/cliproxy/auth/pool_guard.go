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
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	internalconfig "github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
)

const PoolGuardVersion = 1

type poolAdmissionError struct{}

func (poolAdmissionError) Error() string         { return "pool account admission required" }
func (poolAdmissionError) StatusCode() int       { return http.StatusForbidden }
func (poolAdmissionError) IsRequestScoped() bool { return true }
func (poolAdmissionError) IsRequestStop() bool   { return true }

var ErrPoolGuard = poolAdmissionError{}

type poolAttemptContextKey struct{}

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
	AuthID           string   `json:"auth_id"`
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
	GuardVersion int         `json:"guard_version"`
	Revision     uint64      `json:"revision"`
	Grants       []PoolGrant `json:"grants"`
}

type poolGuard struct {
	role         string
	file         string
	mu           sync.RWMutex
	countsMu     sync.Mutex
	counts       map[string]int
	lastRevision uint64
}

func newPoolGuard() *poolGuard {
	role := strings.TrimSpace(os.Getenv("CLEARAPI_POOL_ROLE"))
	if role == "" {
		return nil
	}
	return &poolGuard{role: role, file: os.Getenv("CLEARAPI_POOL_ADMISSION_FILE"), counts: make(map[string]int)}
}

func (m *Manager) PoolRole() string {
	if m == nil || m.poolGuard == nil {
		return ""
	}
	return m.poolGuard.role
}

// PoolCredentialDigest hashes the execution credential in memory. It never
// returns credential contents. Rotation changes the digest and closes admission
// until a trusted promotion updates the separate grant; refresh cannot self-admit.
func PoolCredentialDigest(auth *Auth) string {
	if auth == nil {
		return ""
	}
	metadata := make(map[string]any, len(auth.Metadata))
	for key, value := range auth.Metadata {
		if key != "disabled" {
			metadata[key] = value
		}
	}
	payload, err := json.Marshal(struct {
		ID         string
		Provider   string
		FileName   string
		Attributes map[string]string
		Metadata   map[string]any
	}{auth.ID, auth.Provider, auth.FileName, auth.Attributes, metadata})
	if err != nil {
		return ""
	}
	digest := sha256.Sum256(payload)
	return hex.EncodeToString(digest[:])
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
	if decoder.Decode(&record) != nil || record.GuardVersion != PoolGuardVersion || record.Revision < 1 || len(record.Grants) > 1024 {
		return nil, ErrPoolGuard
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return nil, ErrPoolGuard
	}
	guard.countsMu.Lock()
	defer guard.countsMu.Unlock()
	if record.Revision < guard.lastRevision {
		return nil, ErrPoolGuard
	}
	guard.lastRevision = record.Revision
	return &record, nil
}

func (m *Manager) poolGrant(auth *Auth, model string, capabilities []string) (*PoolGrant, error) {
	guard := m.poolGuard
	if guard == nil {
		return nil, nil
	}
	if guard.role != "service" || auth == nil || auth.AuthKind() != AuthKindOAuth || auth.Disabled || auth.Status == StatusDisabled || auth.Unavailable {
		return nil, ErrPoolGuard
	}
	cfg, _ := m.runtimeConfig.Load().(*internalconfig.Config)
	if cfg == nil || cfg.AuthDir == "" {
		return nil, ErrPoolGuard
	}
	authRoot, err := filepath.Abs(cfg.AuthDir)
	if err != nil {
		return nil, ErrPoolGuard
	}
	grantPath, err := filepath.Abs(guard.file)
	if err != nil {
		return nil, ErrPoolGuard
	}
	root, err := filepath.EvalSymlinks(authRoot)
	file, fileErr := filepath.EvalSymlinks(grantPath)
	if err != nil || fileErr != nil || file == root || strings.HasPrefix(file, root+string(os.PathSeparator)) {
		return nil, ErrPoolGuard
	}
	record, err := guard.grants()
	if err != nil {
		return nil, err
	}
	digest := PoolCredentialDigest(auth)
	now := time.Now().Unix()
	var match *PoolGrant
	for i := range record.Grants {
		grant := &record.Grants[i]
		if grant.AuthID != auth.ID {
			continue
		}
		if match != nil {
			return nil, ErrPoolGuard
		}
		match = grant
	}
	if match == nil || !match.Enabled || match.Provider != auth.Provider || digest == "" || match.CredentialDigest != digest || match.ExpiresAt <= now || match.ExpiresAt > now+1800 || match.MaxConcurrency < 1 || match.MaxConcurrency > 64 || len(match.SourceEvidence) == 0 || len(match.TestEvidence) == 0 || !slices.Contains(match.Models, model) {
		return nil, ErrPoolGuard
	}
	for _, reference := range append(slices.Clone(match.SourceEvidence), match.TestEvidence...) {
		if strings.TrimSpace(reference) == "" {
			return nil, ErrPoolGuard
		}
	}
	for _, capability := range append([]string{"text_chat", "exact_usage"}, capabilities...) {
		if !slices.Contains(match.Capabilities, capability) {
			return nil, ErrPoolGuard
		}
		if capability == "tools" && !match.NativeTools {
			return nil, ErrPoolGuard
		}
	}
	return match, nil
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
				if key == "tools" || key == "functions" || key == "tool_calls" || key == "function_call" || key == "tool_use" || key == "tool_result" {
					caps = append(caps, "tools")
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

func (executor *poolExecutor) begin(ctx context.Context, auth *Auth, req cliproxyexecutor.Request, stream bool, consumeAttempt bool) (func(), error) {
	guard := executor.manager.poolGuard
	guard.mu.RLock()
	if auth == nil {
		guard.mu.RUnlock()
		return nil, ErrPoolGuard
	}
	executor.manager.mu.RLock()
	current := executor.manager.auths[auth.ID]
	currentMatches := current != nil && !current.Disabled && current.Status != StatusDisabled && PoolCredentialDigest(current) == PoolCredentialDigest(auth)
	executor.manager.mu.RUnlock()
	if !currentMatches {
		guard.mu.RUnlock()
		return nil, ErrPoolGuard
	}
	caps, err := poolRequestCapabilities(req, stream)
	if err != nil {
		guard.mu.RUnlock()
		return nil, err
	}
	grant, err := executor.manager.poolGrant(auth, req.Model, caps)
	if err != nil {
		guard.mu.RUnlock()
		return nil, err
	}
	if consumeAttempt {
		budget, _ := ctx.Value(poolAttemptContextKey{}).(*atomic.Bool)
		if budget == nil || !budget.CompareAndSwap(false, true) {
			guard.mu.RUnlock()
			return nil, ErrPoolGuard
		}
	}
	guard.countsMu.Lock()
	if guard.counts[auth.ID] >= grant.MaxConcurrency {
		guard.countsMu.Unlock()
		guard.mu.RUnlock()
		return nil, ErrPoolGuard
	}
	guard.counts[auth.ID]++
	guard.countsMu.Unlock()
	return func() { guard.countsMu.Lock(); guard.counts[auth.ID]--; guard.countsMu.Unlock(); guard.mu.RUnlock() }, nil
}

func (executor *poolExecutor) Execute(ctx context.Context, auth *Auth, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
	release, err := executor.begin(ctx, auth, req, false, true)
	if err != nil {
		return cliproxyexecutor.Response{}, err
	}
	defer release()
	return executor.ProviderExecutor.Execute(ctx, auth, req, opts)
}

func (executor *poolExecutor) ExecuteStream(ctx context.Context, auth *Auth, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) (*cliproxyexecutor.StreamResult, error) {
	release, err := executor.begin(ctx, auth, req, true, true)
	if err != nil {
		return nil, err
	}
	result, err := executor.ProviderExecutor.ExecuteStream(ctx, auth, req, opts)
	if err != nil || result == nil {
		release()
		return result, err
	}
	chunks := make(chan cliproxyexecutor.StreamChunk)
	go func() {
		defer close(chunks)
		defer release()
		for {
			select {
			case <-ctx.Done():
				return
			case chunk, ok := <-result.Chunks:
				if !ok {
					return
				}
				select {
				case chunks <- chunk:
				case <-ctx.Done():
					return
				}
			}
		}
	}()
	return &cliproxyexecutor.StreamResult{Headers: result.Headers, Chunks: chunks}, nil
}

func (executor *poolExecutor) CountTokens(ctx context.Context, auth *Auth, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
	release, err := executor.begin(ctx, auth, req, false, true)
	if err != nil {
		return cliproxyexecutor.Response{}, err
	}
	defer release()
	return executor.ProviderExecutor.CountTokens(ctx, auth, req, opts)
}

func (executor *poolExecutor) HttpRequest(context.Context, *Auth, *http.Request) (*http.Response, error) {
	return nil, ErrPoolGuard
}

func (executor *poolExecutor) Refresh(ctx context.Context, auth *Auth) (*Auth, error) {
	release, err := executor.begin(ctx, auth, cliproxyexecutor.Request{Model: firstPoolGrantModel(executor.manager, auth)}, false, false)
	if err != nil {
		return nil, err
	}
	defer release()
	return executor.ProviderExecutor.Refresh(ctx, auth)
}

func quarantinePoolAuth(auth *Auth) {
	auth.Disabled, auth.Status = true, StatusDisabled
	if auth.Metadata == nil {
		auth.Metadata = make(map[string]any)
	}
	auth.Metadata["disabled"] = true
}
