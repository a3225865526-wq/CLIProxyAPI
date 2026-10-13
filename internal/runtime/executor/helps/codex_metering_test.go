package helps

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"testing"

	chat "github.com/router-for-me/CLIProxyAPI/v8/internal/translator/codex/openai/chat-completions"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/usage"
	"github.com/tidwall/gjson"
)

func TestCodexMeteringGolden(t *testing.T) {
	data, err := os.ReadFile("testdata/codex-metering.json")
	if err != nil {
		t.Fatal(err)
	}
	var cases []struct {
		Name           string
		Usage          json.RawMessage
		Status, Reason string
		Derived        bool
	}
	if err := json.Unmarshal(data, &cases); err != nil {
		t.Fatal(err)
	}
	for _, tc := range cases {
		t.Run(tc.Name, func(t *testing.T) {
			m := usage.ParseCodexMetering(tc.Usage)
			if m.Status != tc.Status || m.Reason != tc.Reason || m.TotalDerived != tc.Derived {
				t.Fatalf("meter = %+v", m)
			}
			if m.Status == "exact" && *m.Total != *m.Input+*m.Output {
				t.Fatal("detail double count")
			}
		})
	}
}

// Only a caller that opts in with the metering request header gets an augmented
// response; every other client keeps the exact upstream payload.
func TestCodexMeteringEnvelopeRequiresOptIn(t *testing.T) {
	raw := []byte(`{"type":"response.completed","response":{"usage":{"input_tokens":5,"output_tokens":1,"total_tokens":6}}}`)
	reporter := NewUsageReporter(context.Background(), "codex", "synthetic-model", nil)
	if got := AnnotateCodexMetering(raw, reporter, false); string(got) != string(raw) {
		t.Fatalf("unrequested metering changed the payload: %s", got)
	}
	requested := http.Header{}
	requested.Set("X-Codex-Metering", "v1")
	if !CodexMeteringRequested(context.Background(), requested) {
		t.Fatal("request header did not opt in")
	}
	if CodexMeteringRequested(context.Background(), http.Header{}) {
		t.Fatal("bare request opted in")
	}
	if gjson.GetBytes(AnnotateCodexMetering(raw, reporter, true), "response.usage.codex_metering").Raw == "" {
		t.Fatal("missing envelope for an opted-in caller")
	}
}

func TestCodexMeteringSurvivesDefaultsAndChatConversion(t *testing.T) {
	for _, raw := range []string{
		`{"type":"response.completed","response":{"id":"synthetic","model":"synthetic-model","usage":{"input_tokens":100,"output_tokens":20,"total_tokens":120,"input_tokens_details":{"cached_tokens":30},"output_tokens_details":{"reasoning_tokens":7}}}}`,
		`{"type":"response.completed","response":{"usage":{"input_tokens":100,"output_tokens":0,"total_tokens":100}}}`,
	} {
		annotated := AnnotateCodexMetering([]byte(raw), NewUsageReporter(context.Background(), "codex", "synthetic-model", nil), true)
		want := gjson.GetBytes(annotated, "response.usage.codex_metering").Raw
		if want == "" {
			t.Fatal("missing envelope")
		}
		patched := EnsureResponsesUsageDetails(annotated)
		if gjson.GetBytes(patched, "response.usage.codex_metering").Raw != want {
			t.Fatal("defaults changed facts")
		}
		var state any
		chunks := chat.ConvertCodexResponseToOpenAI(context.Background(), "synthetic-model", nil, nil, append([]byte("data: "), annotated...), &state)
		if len(chunks) == 0 || gjson.GetBytes(chunks[0], "usage.codex_metering").Raw != want {
			t.Fatal("stream Chat lost meter")
		}
		out := chat.ConvertCodexResponseToOpenAINonStream(context.Background(), "synthetic-model", nil, nil, annotated, nil)
		if gjson.GetBytes(out, "usage.codex_metering").Raw != want {
			t.Fatal("nonstream Chat lost meter")
		}
	}
}
