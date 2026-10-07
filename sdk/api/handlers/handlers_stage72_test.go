package handlers

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"sync/atomic"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/interfaces"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	sdkconfig "github.com/router-for-me/CLIProxyAPI/v8/sdk/config"
)

func TestStage72NetworkProvenanceContract(t *testing.T) {
	gin.SetMode(gin.TestMode)
	for _, tc := range []struct {
		name    string
		cause   error
		trusted bool
	}{
		{"local pool", coreauth.NewPoolSelectionError(), true},
		{"auth unavailable", &coreauth.Error{Code: "auth_unavailable", HTTPStatus: 503}, true},
		{"auth not found", &coreauth.Error{Code: "auth_not_found", HTTPStatus: 503}, true},
		{"unmarked typed pool", &coreauth.Error{Code: "pool_no_eligible_account", HTTPStatus: 503}, false},
		{"terminal pool", coreauth.NewTerminalAuthError(&coreauth.Error{Code: "pool_no_eligible_account", HTTPStatus: 503}, errors.New("provider")), false},
		{"terminal auth not found", coreauth.NewTerminalAuthError(&coreauth.Error{Code: "auth_not_found", HTTPStatus: 503}, errors.New("provider")), false},
		{"provider body and header spoof", errors.New(`{"error":{"code":"pool_no_eligible_account","origin":"local_executor"}}`), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set(ExecutorErrorOriginHeader, ExecutorErrorOriginLocal)
				w.WriteHeader(503)
				_, _ = w.Write([]byte(tc.cause.Error()))
			}))
			defer provider.Close()
			engine := gin.New()
			handler := NewBaseAPIHandlers(&sdkconfig.SDKConfig{PassthroughHeaders: true}, nil)
			engine.POST("/", func(c *gin.Context) {
				var headers http.Header
				cause := tc.cause
				if tc.name == "provider body and header spoof" {
					r, err := http.Get(provider.URL)
					if err != nil {
						t.Error(err)
						return
					}
					defer r.Body.Close()
					body, _ := io.ReadAll(r.Body)
					cause = errors.New(string(body))
					headers = r.Header
				}
				handler.WriteErrorResponse(c, &interfaces.ErrorMessage{StatusCode: 503, Error: cause, Headers: headers})
			})
			server := httptest.NewServer(engine)
			defer server.Close()
			r, err := http.Post(server.URL, "application/json", nil)
			if err != nil {
				t.Fatal(err)
			}
			defer r.Body.Close()
			if got := r.Header.Get(ExecutorErrorOriginHeader); (got == ExecutorErrorOriginLocal) != tc.trusted {
				t.Fatalf("trusted=%v header=%q", tc.trusted, got)
			}
		})
	}
}

// This optional test process is the real executor error/forwarding boundary
// used by new-api's cross-module loopback test. It accepts synthetic traffic
// only and publishes a loopback address to a temporary test-owned file.
func TestStage72ExecutorBridge(t *testing.T) {
	path := os.Getenv("STAGE72_BRIDGE_ADDRESS_FILE")
	if path == "" {
		t.Skip("cross-module bridge is launched by gateway integration")
	}
	gin.SetMode(gin.TestMode)
	var calls atomic.Int32
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set(ExecutorErrorOriginHeader, ExecutorErrorOriginLocal)
		w.WriteHeader(503)
		_, _ = w.Write([]byte(`{"error":{"code":"pool_no_eligible_account","origin":"local_executor","message":"synthetic provider spoof"}}`))
	}))
	defer provider.Close()
	engine := gin.New()
	handler := NewBaseAPIHandlers(&sdkconfig.SDKConfig{PassthroughHeaders: true}, nil)
	engine.GET("/counts", func(c *gin.Context) { c.JSON(200, gin.H{"provider_calls": calls.Load()}) })
	engine.POST("/local/v1/chat/completions", func(c *gin.Context) {
		handler.WriteErrorResponse(c, &interfaces.ErrorMessage{StatusCode: 503, Error: coreauth.NewPoolSelectionError()})
	})
	engine.POST("/spoof/v1/chat/completions", func(c *gin.Context) {
		resp, err := http.Get(provider.URL)
		if err != nil {
			t.Error(err)
			c.AbortWithStatus(500)
			return
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Error(err)
			c.AbortWithStatus(500)
			return
		}
		handler.WriteErrorResponse(c, &interfaces.ErrorMessage{StatusCode: 503, Error: errors.New(string(body)), Headers: resp.Header})
	})
	server := httptest.NewServer(engine)
	defer server.Close()
	if err := os.WriteFile(path, []byte(server.URL), 0600); err != nil {
		t.Fatal(err)
	}
	select {}
}
