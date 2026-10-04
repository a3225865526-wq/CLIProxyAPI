package api

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	sdkhandlers "github.com/router-for-me/CLIProxyAPI/v8/sdk/api/handlers"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
)

func TestPoolGuardServiceManagementRejectsAuthorizationImportAndProxy(t *testing.T) {
	t.Setenv("CLEARAPI_POOL_ROLE", "service")
	manager := auth.NewManager(nil, nil, nil)
	server := &Server{cfg: &config.Config{}, handlers: &sdkhandlers.BaseAPIHandler{AuthManager: manager}}
	server.managementRoutesEnabled.Store(true)
	engine := gin.New()
	calls := 0
	engine.Any("/v0/management/*path", server.managementAvailabilityMiddleware(), func(c *gin.Context) { calls++; c.Status(http.StatusNoContent) })
	for _, test := range []struct{ method, path string }{
		{http.MethodGet, "/v0/management/codex-auth-url"},
		{http.MethodPost, "/v0/management/oauth-callback"},
		{http.MethodPost, "/v0/management/auth-files"},
		{http.MethodGet, "/v0/management/auth-files/download"},
		{http.MethodPut, "/v0/management/config.yaml"},
		{http.MethodPost, "/v0/management/api-call"},
	} {
		response := httptest.NewRecorder()
		engine.ServeHTTP(response, httptest.NewRequest(test.method, test.path, nil))
		if response.Code != http.StatusForbidden {
			t.Fatalf("%s %s accepted", test.method, test.path)
		}
	}
	if calls != 0 {
		t.Fatal("restricted management operation reached handler")
	}
	response := httptest.NewRecorder()
	engine.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/v0/management/auth-files", nil))
	if response.Code != http.StatusNoContent || calls != 1 {
		t.Fatal("metadata inspection unexpectedly blocked")
	}
}
