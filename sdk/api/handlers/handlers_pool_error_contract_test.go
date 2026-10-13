package handlers

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/interfaces"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	sdkconfig "github.com/router-for-me/CLIProxyAPI/v8/sdk/config"
	"net/http/httptest"
)

// Contract tests for the Resilient Route Chain on the new-api side
// (docs/superpowers/specs/2026-10-06-resilient-route-chain-design.md, C4):
// executor pool exhaustion must reach downstream routers as a structured,
// machine-readable error.code — never only as message text — and a real
// upstream response body forwarded verbatim must keep its own code.
func TestBuildErrorResponseBodyCarriesPoolExhaustionCode(t *testing.T) {
	err := &coreauth.Error{Code: "auth_unavailable", Message: "no auth available", HTTPStatus: http.StatusServiceUnavailable, Retryable: true}
	body := BuildErrorResponseBodyWithError(http.StatusServiceUnavailable, err.Error(), err)

	var envelope struct {
		Error struct {
			Code   string `json:"code"`
			Type   string `json:"type"`
			Origin string `json:"origin"`
		} `json:"error"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		t.Fatalf("body is not a JSON envelope: %v\nbody: %s", err, body)
	}
	if envelope.Error.Code != "auth_unavailable" {
		t.Fatalf("expected error.code auth_unavailable on the wire, got %q (body: %s)", envelope.Error.Code, body)
	}
	if envelope.Error.Type != "server_error" {
		t.Fatalf("expected server_error type for 503, got %q", envelope.Error.Type)
	}
	if envelope.Error.Origin != "local_executor" {
		t.Fatalf("expected executor provenance origin=local_executor, got %q (body: %s)", envelope.Error.Origin, body)
	}
}

func TestBuildErrorResponseBodyCarriesAuthNotFoundCode(t *testing.T) {
	err := &coreauth.Error{Code: "auth_not_found", Message: "no auth available"}
	body := BuildErrorResponseBodyWithError(http.StatusServiceUnavailable, err.Error(), err)
	if want := `"code":"auth_not_found"`; !bytes.Contains(body, []byte(want)) {
		t.Fatalf("expected %s in body, got %s", want, body)
	}
}

func TestBuildErrorResponseBodyKeepsUpstreamBodyVerbatim(t *testing.T) {
	// A real upstream 503 whose body is valid JSON must be forwarded
	// unchanged — it must never be re-labeled as pool exhaustion.
	upstream := []byte(`{"error":{"message":"upstream overloaded","type":"server_error","code":"provider_overloaded"}}`)
	body := BuildErrorResponseBodyWithError(http.StatusServiceUnavailable, string(upstream), nil)
	if string(body) != string(upstream) {
		t.Fatalf("upstream body must be forwarded verbatim, got %s", body)
	}
}

// Provenance contract (Stage 4): only executor-synthesized errors carry
// origin=local_executor. A real provider error echoing auth_unavailable with
// untrusted provenance must stay distinguishable, and status-derived fallback
// codes must never claim executor origin.
func TestBuildErrorResponseBodyProviderEchoCarriesNoExecutorOrigin(t *testing.T) {
	// A provider body echoing the exhaustion code is forwarded verbatim and
	// must NOT gain executor provenance.
	upstream := []byte(`{"error":{"message":"upstream echoed","type":"server_error","code":"auth_unavailable"}}`)
	body := BuildErrorResponseBodyWithError(http.StatusServiceUnavailable, string(upstream), nil)
	var envelope struct {
		Error struct {
			Origin string `json:"origin"`
			Code   string `json:"code"`
		} `json:"error"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		t.Fatalf("body is not a JSON envelope: %v\nbody: %s", err, body)
	}
	if envelope.Error.Origin != "" {
		t.Fatalf("forwarded provider body must not gain executor provenance, got origin=%q (body: %s)", envelope.Error.Origin, body)
	}
}

func TestBuildErrorResponseBodyStatusFallbackCarriesNoExecutorOrigin(t *testing.T) {
	body := BuildErrorResponseBodyWithError(http.StatusInternalServerError, "boom", nil)
	var envelope struct {
		Error struct {
			Origin string `json:"origin"`
		} `json:"error"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		t.Fatalf("body is not a JSON envelope: %v\nbody: %s", err, body)
	}
	if envelope.Error.Origin != "" {
		t.Fatalf("status-derived fallback must not claim executor provenance, got origin=%q (body: %s)", envelope.Error.Origin, body)
	}
}

func TestBuildErrorResponseBodyAuthNotFoundCarriesExecutorOrigin(t *testing.T) {
	err := &coreauth.Error{Code: "auth_not_found", Message: "no auth available"}
	body := BuildErrorResponseBodyWithError(http.StatusServiceUnavailable, err.Error(), err)
	if want := `"origin":"local_executor"`; !bytes.Contains(body, []byte(want)) {
		t.Fatalf("expected %s in body, got %s", want, body)
	}
}

// Stage 7.1 provenance hardening: the trusted provenance signal moves from the
// provider-forgeable body origin to a CPA-reserved transport header. The
// header is stamped only on locally synthesized exhaustion envelopes and is
// stripped from every forwarded upstream response.

func writeErrorResponseForTest(t *testing.T, status int, errCause error, upstreamHeaders http.Header) *httptest.ResponseRecorder {
	t.Helper()
	gin.SetMode(gin.TestMode)
	recorder := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(recorder)
	c.Request = httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil)
	handler := NewBaseAPIHandlers(nil, nil)
	handler.WriteErrorResponse(c, &interfaces.ErrorMessage{
		StatusCode: status,
		Error:      errCause,
		Headers:    upstreamHeaders,
	})
	return recorder
}

// L1 (executor side): a locally synthesized auth_unavailable envelope carries
// the trusted transport header.
func TestWriteErrorResponseStampsExecutorOriginHeaderOnAuthUnavailable(t *testing.T) {
	err := &coreauth.Error{Code: "auth_unavailable", Message: "no auth available", HTTPStatus: http.StatusServiceUnavailable}
	recorder := writeErrorResponseForTest(t, http.StatusServiceUnavailable, err, nil)
	if got := recorder.Header().Get(ExecutorErrorOriginHeader); got != ExecutorErrorOriginLocal {
		t.Fatalf("expected %s: %s on a locally synthesized exhaustion envelope, got %q", ExecutorErrorOriginHeader, ExecutorErrorOriginLocal, got)
	}
}

// L2 (executor side): same for auth_not_found.
func TestWriteErrorResponseStampsExecutorOriginHeaderOnAuthNotFound(t *testing.T) {
	err := &coreauth.Error{Code: "auth_not_found", Message: "no auth available", HTTPStatus: http.StatusServiceUnavailable}
	recorder := writeErrorResponseForTest(t, http.StatusServiceUnavailable, err, nil)
	if got := recorder.Header().Get(ExecutorErrorOriginHeader); got != ExecutorErrorOriginLocal {
		t.Fatalf("expected %s: %s on a locally synthesized auth_not_found envelope, got %q", ExecutorErrorOriginHeader, ExecutorErrorOriginLocal, got)
	}
}

// Scope check: terminal auth errors are executor-local too, but their code is
// not in the gateway's exhaustion trust set, so they are never stamped.
func TestWriteErrorResponseNoExecutorOriginHeaderForTerminalAuthError(t *testing.T) {
	err := coreauth.NewTerminalAuthError(&coreauth.Error{Code: "upstream_authentication_required", Message: "terminal"}, errors.New("terminal"))
	recorder := writeErrorResponseForTest(t, http.StatusServiceUnavailable, err, nil)
	if got := recorder.Header().Get(ExecutorErrorOriginHeader); got != "" {
		t.Fatalf("terminal auth error must not carry the provenance header, got %q", got)
	}
}

// P1/P2 (executor side): a provider-echoed exhaustion body is forwarded
// verbatim and must not gain the trusted header.
func TestWriteErrorResponseProviderEchoCarriesNoExecutorOriginHeader(t *testing.T) {
	upstream := `{"error":{"message":"provider echoed","type":"server_error","code":"auth_unavailable","origin":"local_executor"}}`
	recorder := writeErrorResponseForTest(t, http.StatusServiceUnavailable, errors.New(upstream), nil)
	if got := recorder.Header().Get(ExecutorErrorOriginHeader); got != "" {
		t.Fatalf("forwarded provider body must not carry the provenance header, got %q", got)
	}
	if !bytes.Contains(recorder.Body.Bytes(), []byte("provider echoed")) {
		t.Fatalf("provider body must stay verbatim, got %s", recorder.Body.String())
	}
}

// P3 (executor side): a provider response that returns the reserved header
// itself must have it stripped before the response reaches a downstream
// router — FilterUpstreamHeaders is the funnel for every forwarded header set.
func TestFilterUpstreamHeadersStripsSpoofedExecutorOriginHeader(t *testing.T) {
	src := http.Header{
		"X-Cpa-Executor-Error-Origin": {"local"},
		"X-Provider-Header":           {"value"},
	}
	filtered := FilterUpstreamHeaders(src)
	if filtered.Get(ExecutorErrorOriginHeader) != "" {
		t.Fatalf("spoofed %s must be stripped from forwarded upstream headers", ExecutorErrorOriginHeader)
	}
	if filtered.Get("X-Provider-Header") != "value" {
		t.Fatalf("unrelated provider headers must survive filtering")
	}
}

// P4 (executor side): even when the error path carries upstream headers
// (passthrough of msg.Headers), a spoofed reserved header is dropped.
func TestWriteErrorResponseStripsSpoofedExecutorOriginHeaderFromUpstreamHeaders(t *testing.T) {
	upstreamHeaders := http.Header{
		"X-Cpa-Executor-Error-Origin": {"local"},
		"X-Provider-Header":           {"value"},
	}
	recorder := writeErrorResponseForTest(t, http.StatusServiceUnavailable, errors.New("provider overloaded"), upstreamHeaders)
	if got := recorder.Header().Get(ExecutorErrorOriginHeader); got != "" {
		t.Fatalf("spoofed %s must never survive forwarding, got %q", ExecutorErrorOriginHeader, got)
	}
	if recorder.Header().Get("X-Provider-Header") == "value" {
		// passthrough of msg.Headers is not enabled by default; either way the
		// reserved header must be absent.
		t.Log("provider header passthrough enabled in this configuration")
	}
}

// P4 (executor side): the addon passthrough (executor-error-owned headers)
// skips reserved headers too, so an error carrier cannot smuggle the marker.
func TestWriteErrorResponseAddonSkipsSpoofedExecutorOriginHeader(t *testing.T) {
	gin.SetMode(gin.TestMode)
	recorder := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(recorder)
	c.Request = httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil)
	handler := NewBaseAPIHandlers(&sdkconfig.SDKConfig{PassthroughHeaders: true}, nil)
	handler.WriteErrorResponse(c, &interfaces.ErrorMessage{
		StatusCode: http.StatusServiceUnavailable,
		Error:      errors.New("boom"),
		Addon: http.Header{
			ExecutorErrorOriginHeader: {"local"},
		},
	})
	if got := recorder.Header().Get(ExecutorErrorOriginHeader); got != "" {
		t.Fatalf("addon passthrough must skip the reserved header, got %q", got)
	}
}
