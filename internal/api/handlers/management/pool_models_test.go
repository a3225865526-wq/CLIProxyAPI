package management

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
)

func TestPoolStage3ManagementAPI(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "auths")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	checkpoint := filepath.Join(root, "checkpoint.jsonl")
	policy := filepath.Join(root, "policy.json")
	t.Setenv("CLEARAPI_POOL_ROLE", "service")
	t.Setenv("CLEARAPI_POOL_EXECUTOR_ID", "synthetic-executor")
	t.Setenv("CLEARAPI_POOL_CHECKPOINT_FILE", checkpoint)
	t.Setenv("CLEARAPI_POOL_ADMISSION_FILE", policy)
	if err := coreauth.ProvisionPoolCheckpoint(checkpoint, "synthetic-executor"); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{AuthDir: dir}
	manager := coreauth.NewManager(nil, nil, nil)
	manager.SetConfig(cfg)
	auth := &coreauth.Auth{ID: "synthetic", Provider: "codex", Status: coreauth.StatusActive, Attributes: map[string]string{coreauth.AttributeAuthKind: coreauth.AuthKindOAuth}, Metadata: map[string]any{"access_token": "synthetic-unused", "account_id": "synthetic-account-id"}}
	identity := coreauth.PoolIdentityExpectation{AuthID: auth.ID, Provider: auth.Provider, CredentialDigest: coreauth.PoolCredentialDigest(auth)}
	record := coreauth.PoolGrantFile{GuardVersion: coreauth.PoolGuardVersion, ExecutorID: "synthetic-executor", Revision: 1, Grants: []coreauth.PoolGrant{{AuthID: auth.ID, Provider: auth.Provider, CredentialDigest: identity.CredentialDigest, Models: []string{"synthetic-native"}, Capabilities: []string{"text_chat", "exact_usage"}, Enabled: true, ExpiresAt: time.Now().Add(10 * time.Minute).Unix(), MaxConcurrency: 1, SourceEvidence: []string{"synthetic"}, TestEvidence: []string{"synthetic"}}}}
	data, _ := json.Marshal(record)
	if err := os.WriteFile(policy, data, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Register(context.Background(), auth); err != nil {
		t.Fatal(err)
	}
	handler := NewHandler(cfg, "", manager)
	engine := gin.New()
	engine.GET("/models", handler.GetPoolModels)
	engine.POST("/models/grant", handler.GrantPoolModel)
	engine.POST("/models/revoke", handler.RevokePoolModel)
	if err := manager.PromotePoolIdentities(context.Background(), coreauth.PoolPromotion{ExpectedRevision: 1, Identities: []coreauth.PoolIdentityExpectation{identity}}); err != nil {
		t.Fatal(err)
	}
	_, states, err := manager.PoolTrustSnapshot()
	if err != nil || len(states) != 1 {
		t.Fatal("trust fixture", err)
	}
	identity.Generation = states[0].Generation
	grant, _ := json.Marshal(coreauth.PoolModelGrant{ExpectedRevision: 2, Identity: identity, Model: "synthetic-native"})
	response := httptest.NewRecorder()
	engine.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/models/grant", bytes.NewReader(grant)))
	if response.Code != http.StatusOK {
		t.Fatal("grant failed", response.Body.String())
	}
	response = httptest.NewRecorder()
	engine.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/models/grant", bytes.NewReader(grant)))
	if response.Code != http.StatusConflict {
		t.Fatal("stale grant accepted")
	}
	response = httptest.NewRecorder()
	engine.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/models", nil))
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"model":"synthetic-native"`) {
		t.Fatal("capability snapshot missing", response.Body.String())
	}
	revoke, _ := json.Marshal(coreauth.PoolModelRevoke{ExpectedRevision: 3, Identity: identity, Model: "synthetic-native"})
	response = httptest.NewRecorder()
	engine.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/models/revoke", bytes.NewReader(revoke)))
	if response.Code != http.StatusOK {
		t.Fatal("revoke failed", response.Body.String())
	}
	for _, body := range []string{string(grant) + ` {}`, `{"expected_revision":4,"unknown":true}`, string(grant) + strings.Repeat(" ", 64*1024) + "{}"} {
		response = httptest.NewRecorder()
		engine.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/models/grant", strings.NewReader(body)))
		if response.Code != http.StatusBadRequest {
			t.Fatal("malformed/oversize capability command accepted", response.Code)
		}
	}
}
