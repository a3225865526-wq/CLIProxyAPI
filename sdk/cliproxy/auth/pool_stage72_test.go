package auth

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strings"
	"testing"

	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
)

func TestStage72RequestToolsSemantics(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		tools      bool
	}{
		{"absent", `{}`, false},
		{"empty", `{"tools":[]}`, false},
		{"null", `{"tools":null}`, false},
		{"declaration", `{"tools":[{"type":"function","name":"x"}]}`, true},
		{"none still conservative", `{"tools":[{"type":"function","name":"x"}],"tool_choice":"none"}`, true},
		{"functions empty", `{"functions":[],"function_call":"none"}`, false},
		{"functions null", `{"functions":null}`, false},
		{"functions nonempty", `{"functions":[{"name":"x"}]}`, true},
		{"controls only", `{"tool_choice":"auto","parallel_tool_calls":true}`, false},
		{"named choice", `{"tool_choice":{"type":"function","name":"x"}}`, true},
		{"required choice", `{"tool_choice":"required"}`, true},
		{"native declarations", `{"functionDeclarations":[{"name":"x"}]}`, true},
		{"native calls", `{"contents":[{"parts":[{"functionCall":{"name":"x"}}]}]}`, true},
		{"native results", `{"contents":[{"parts":[{"functionResponse":{"name":"x"}}]}]}`, true},
		{"native choice none", `{"toolConfig":{"functionCallingConfig":{"mode":"NONE"}}}`, false},
		{"native choice any", `{"toolConfig":{"functionCallingConfig":{"mode":"ANY"}}}`, true},
		{"native named choice", `{"toolConfig":{"functionCallingConfig":{"allowedFunctionNames":["x"]}}}`, true},
		{"empty calls", `{"tool_calls":[]}`, false},
		{"tool role", `{"messages":[{"role":"tool","content":"x"}]}`, true},
		{"result type", `{"input":[{"type":"function_call_output","output":"x"}]}`, true},
		{"invalid declaration shape", `{"tools":{}}`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			caps, err := poolRequestCapabilities(cliproxyexecutor.Request{Payload: []byte(tc.body)}, false)
			if err != nil || slices.Contains(caps, "tools") != tc.tools {
				t.Fatalf("caps=%v err=%v", caps, err)
			}
		})
	}
}

// Both ingress and the scripted provider use real TCP. Only synthetic fixture
// identities are installed; no real credentials or external URLs are used.
type stage72HTTPExecutor struct {
	*poolProbeExecutor
	url string
}

func (e *stage72HTTPExecutor) Execute(ctx context.Context, _ *Auth, req cliproxyexecutor.Request, _ cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
	if err := cliproxyexecutor.BeforeUpstreamDispatch(ctx); err != nil {
		return cliproxyexecutor.Response{}, err
	}
	r, err := http.NewRequestWithContext(ctx, http.MethodPost, e.url, strings.NewReader(string(req.Payload)))
	if err != nil {
		return cliproxyexecutor.Response{}, err
	}
	resp, err := http.DefaultClient.Do(r)
	if err != nil {
		return cliproxyexecutor.Response{}, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	return cliproxyexecutor.Response{Payload: body}, err
}

func TestStage72NetworkEligibilityParity(t *testing.T) {
	for _, tc := range []struct {
		name, body     string
		tools, allowed bool
	}{
		{"E1 absent", `{}`, false, true},
		{"E2 empty", `{"tools":[]}`, false, true},
		{"E3 unauthorized tools", `{"tools":[{"type":"function","name":"x"}]}`, false, false},
		{"E4 authorized tools", `{"tools":[{"type":"function","name":"x"}]}`, true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m, probe, _, _, _ := poolGuardFixture(t, "service", tc.tools)
			provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				probe.calls.Add(1)
				_, _ = w.Write([]byte(`{"usage":{"input_tokens":1,"output_tokens":1,"total_tokens":2}}`))
			}))
			defer provider.Close()
			m.RegisterExecutor(&stage72HTTPExecutor{poolProbeExecutor: probe, url: provider.URL})
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				body, _ := io.ReadAll(r.Body)
				opts := cliproxyexecutor.Options{OriginalRequest: body}
				if r.URL.Path == "/preflight" {
					result, err := m.PoolRequestPreflight(r.Context(), "synthetic-native", opts)
					if err != nil {
						t.Error(err)
						w.WriteHeader(500)
						return
					}
					_ = json.NewEncoder(w).Encode(result)
					return
				}
				resp, err := m.Execute(r.Context(), []string{"codex"}, cliproxyexecutor.Request{Model: "synthetic-native", Payload: body}, opts)
				if err != nil {
					if !IsLocalPoolSelectionError(err) {
						t.Error("rejection lost local provenance")
					}
					w.WriteHeader(503)
					return
				}
				_, _ = w.Write(resp.Payload)
			}))
			defer server.Close()
			journalBefore, err := os.ReadFile(m.poolGuard.checkpoint)
			if err != nil {
				t.Fatal(err)
			}
			response, err := http.Post(server.URL+"/preflight", "application/json", strings.NewReader(tc.body))
			if err != nil {
				t.Fatal(err)
			}
			var result PoolPreflightResult
			if err := json.NewDecoder(response.Body).Decode(&result); err != nil {
				t.Fatal(err)
			}
			response.Body.Close()
			if probe.calls.Load() != 0 {
				t.Fatal("preflight dispatched")
			}
			journalAfter, err := os.ReadFile(m.poolGuard.checkpoint)
			if err != nil || string(journalBefore) != string(journalAfter) {
				t.Fatal("preflight mutated journal", err)
			}
			response, err = http.Post(server.URL+"/execute", "application/json", strings.NewReader(tc.body))
			if err != nil {
				t.Fatal(err)
			}
			response.Body.Close()
			if (result.EligibleCount == 1) != tc.allowed || (response.StatusCode == 200) != tc.allowed {
				t.Fatalf("preflight=%+v runtime=%d", result, response.StatusCode)
			}
			want := int32(0)
			if tc.allowed {
				want = 1
			}
			if probe.calls.Load() != want {
				t.Fatalf("provider calls=%d want=%d", probe.calls.Load(), want)
			}
		})
	}
}

func TestStage72LocalPoolMarkerRejectsPriorWork(t *testing.T) {
	if IsLocalPoolSelectionError(markUpstreamExecutionAttempt(NewPoolSelectionError())) {
		t.Fatal("prior provider work trusted")
	}
	if IsLocalPoolSelectionError(&Error{Code: "pool_no_eligible_account", HTTPStatus: 503}) {
		t.Fatal("unmarked typed provider error trusted")
	}
}
