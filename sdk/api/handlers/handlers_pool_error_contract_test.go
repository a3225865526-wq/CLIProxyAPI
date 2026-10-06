package handlers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"testing"

	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
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
