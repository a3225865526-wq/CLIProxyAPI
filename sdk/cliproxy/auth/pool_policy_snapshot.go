package auth

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
	"github.com/tidwall/gjson"
)

const pg03PolicyHeader = "X-ClearAPI-PG03-Policy"
const pg03SignatureHeader = "X-ClearAPI-PG03-Signature"
const pg03RequestHeader = "X-ClearAPI-PG03-Request"

// Field order is the v1 canonical wire format, shared with Gateway.
type pg03PolicySnapshot struct {
	PolicyID         int      `json:"policy_id"`
	PoolID           string   `json:"pool_id"`
	ModelName        string   `json:"model_name"`
	AccountOrder     []string `json:"account_order"`
	MaxFallbackCount int      `json:"max_fallback_count"`
	RequestID        string   `json:"request_id"`
	Method           string   `json:"method"`
	Path             string   `json:"path"`
	BodyDigest       string   `json:"body_digest"`
	IssuedAt         int64    `json:"issued_at"`
}

// Verify before selecting any account. A present but invalid snapshot can never
// fall back to legacy selection. Durable BEGIN receipt uniqueness also prevents
// replay of the same signed request/account after process restart.
func (m *Manager) pg03Policy(ctx context.Context, providers []string, opts cliproxyexecutor.Options) (*pg03PolicySnapshot, []string, error) {
	headers := opts.Headers
	if ctx == nil {
		ctx = context.Background()
	}
	if c, ok := ctx.Value("gin").(*gin.Context); ok && c != nil && c.Request != nil {
		headers = c.Request.Header
	}
	present := false
	for _, name := range []string{pg03PolicyHeader, pg03SignatureHeader, pg03RequestHeader} {
		_, exists := headers[http.CanonicalHeaderKey(name)]
		present = present || exists
	}
	if !present {
		return nil, nil, nil
	}
	if !isPoolAttemptContext(ctx) || !poolResponsesSSEAdmitted(ctx, opts) || len(providers) != 1 || providers[0] != "codex" || m.poolGuard == nil || m.HomeEnabled() || m.hasPluginScheduler() {
		return nil, nil, ErrPoolGuard
	}
	for _, name := range []string{pg03PolicyHeader, pg03SignatureHeader, pg03RequestHeader} {
		if len(headers.Values(name)) != 1 || headers.Get(name) == "" {
			return nil, nil, ErrPoolGuard
		}
	}
	key := os.Getenv("CLEARAPI_PG03_POLICY_KEY")
	encoded := headers.Get(pg03PolicyHeader)
	if len(key) < 32 || len(encoded) > 8192 {
		return nil, nil, ErrPoolGuard
	}
	payload, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return nil, nil, ErrPoolGuard
	}
	signature, err := hex.DecodeString(headers.Get(pg03SignatureHeader))
	if err != nil {
		return nil, nil, ErrPoolGuard
	}
	mac := hmac.New(sha256.New, []byte(key))
	mac.Write([]byte("clearapi-pg03-policy-v1\n"))
	mac.Write(payload)
	if !hmac.Equal(signature, mac.Sum(nil)) {
		return nil, nil, ErrPoolGuard
	}
	var policy pg03PolicySnapshot
	if json.Unmarshal(payload, &policy) != nil {
		return nil, nil, ErrPoolGuard
	}
	canonical, err := json.Marshal(policy)
	if err != nil || !bytes.Equal(canonical, payload) {
		return nil, nil, ErrPoolGuard
	}
	if opts.Headers.Get("X-ClearAPI-PG02-Request") != policy.RequestID || opts.Headers.Get("X-ClearAPI-PG02-Attempt") != policy.RequestID+"-attempt" {
		return nil, nil, ErrPoolGuard
	}
	digest := sha256.Sum256(opts.OriginalRequest)
	requestPath, _ := opts.Metadata[cliproxyexecutor.RequestPathMetadataKey].(string)
	now := time.Now().Unix()
	if policy.PolicyID <= 0 || policy.PoolID == "" || policy.Method != http.MethodPost || policy.Path != requestPath || policy.Path != "/v1/responses" || policy.RequestID == "" || len(policy.RequestID) > 128 || policy.RequestID != headers.Get(pg03RequestHeader) || policy.ModelName != gjson.GetBytes(opts.OriginalRequest, "model").String() || policy.BodyDigest != hex.EncodeToString(digest[:]) || policy.IssuedAt > now+30 || policy.IssuedAt < now-300 || policy.MaxFallbackCount < 0 || policy.MaxFallbackCount > 3 || len(policy.AccountOrder) == 0 || len(policy.AccountOrder) > 4 {
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
			// Match the management auth-file "name" projection exactly. Its
			// defined fallback for records without FileName is the auth ID.
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
