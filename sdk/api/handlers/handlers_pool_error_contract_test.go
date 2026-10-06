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
			Code string `json:"code"`
			Type string `json:"type"`
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
