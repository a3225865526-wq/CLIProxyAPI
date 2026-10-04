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

func TestPoolStage1BManagementPromotionRevocationAndCAS(t *testing.T) {
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
	auth := &coreauth.Auth{ID: "synthetic", Provider: "codex", Status: coreauth.StatusActive, Attributes: map[string]string{coreauth.AttributeAuthKind: coreauth.AuthKindOAuth}, Metadata: map[string]any{"access_token": "synthetic-unused"}}
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
	engine.GET("/trust", handler.GetPoolTrust)
	engine.POST("/promote", handler.PromotePoolTrust)
	engine.POST("/revoke", handler.RevokePoolTrust)
	promotion := coreauth.PoolPromotion{ExpectedRevision: 1, Identities: []coreauth.PoolIdentityExpectation{identity}}
	data, _ = json.Marshal(promotion)
	response := httptest.NewRecorder()
	engine.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/promote", bytes.NewReader(data)))
	if response.Code != http.StatusOK {
		t.Fatal("promotion failed", response.Body.String())
	}
	response = httptest.NewRecorder()
	engine.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/promote", bytes.NewReader(data)))
	if response.Code != http.StatusConflict {
		t.Fatal("duplicate promotion accepted")
	}
	identity.Generation = 2
	revoke, _ := json.Marshal(coreauth.PoolRevocation{ExpectedRevision: 2, Identity: identity})
	response = httptest.NewRecorder()
	engine.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/revoke", bytes.NewReader(revoke)))
	if response.Code != http.StatusOK {
		t.Fatal("revoke failed", response.Body.String())
	}
	response = httptest.NewRecorder()
	engine.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/trust", nil))
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"state":"revoked"`) {
		t.Fatal("revoke state missing")
	}
	for _, body := range []string{string(data) + ` {}`, `{"expected_revision":3,"unknown":true}`, string(data) + strings.Repeat(" ", 64*1024) + "{}"} {
		response = httptest.NewRecorder()
		engine.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/promote", strings.NewReader(body)))
		if response.Code != http.StatusBadRequest {
			t.Fatal("malformed/oversize control accepted", response.Code)
		}
	}
}
