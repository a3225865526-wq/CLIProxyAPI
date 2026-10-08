package handlers

import (
	"errors"
	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/interfaces"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	sdkconfig "github.com/router-for-me/CLIProxyAPI/v8/sdk/config"
	"net/http/httptest"
	"testing"
)

func TestResolverZeroDispatchWireProof(t *testing.T) {
	h := NewBaseAPIHandlers(&sdkconfig.SDKConfig{}, coreauth.NewManager(nil, nil, nil))
	_, _, err := h.getRequestDetails("not-registered-remediation-model")
	if err == nil || !coreauth.IsLocalModelResolutionError(err.Error) {
		t.Fatal("resolver did not return typed proof")
	}
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	h.WriteErrorResponse(c, err)
	if w.Code != 400 || w.Header().Get(ExecutorErrorOriginHeader) != "local" || w.Header().Get(ExecutorDispatchPhaseHeader) != "model_resolution" || w.Header().Get(ExecutorProviderTransportHeader) != "not_started" {
		t.Fatal("trusted wire proof incomplete")
	}
	for _, direct := range []bool{false, true} {
		w = httptest.NewRecorder()
		c, _ = gin.CreateTestContext(w)
		c.Request = httptest.NewRequest("POST", "/v1/responses", nil)
		c.Request.Header.Set(ExecutorProviderTransportHeader, "not_started")
		c.Request.Header.Set(ExecutorDispatchPhaseHeader, "model_resolution")
		c.Request.Header.Set(ExecutorErrorOriginHeader, "local")
		msg := &interfaces.ErrorMessage{StatusCode: 400, Error: errors.New(`{"error":{"code":"model_not_found"}}`), DirectResponse: direct, Body: []byte(`{"error":{"code":"model_not_found"}}`), Headers: w.Header().Clone()}
		msg.Headers.Set(ExecutorErrorOriginHeader, "local")
		msg.Headers.Set(ExecutorDispatchPhaseHeader, "model_resolution")
		msg.Headers.Set(ExecutorProviderTransportHeader, "not_started")
		msg.Addon = msg.Headers.Clone()
		h.WriteErrorResponse(c, msg)
		if w.Header().Get(ExecutorErrorOriginHeader) != "" || w.Header().Get(ExecutorDispatchPhaseHeader) != "" || w.Header().Get(ExecutorProviderTransportHeader) != "" {
			t.Fatal("client/provider spoof accepted")
		}
	}
}
