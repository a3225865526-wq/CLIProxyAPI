package helps

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/usage"
	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
)

// AnnotateCodexMetering runs before protocol conversion/default synthesis.
// Only response objects carry the extension; delta counters are not usage.
// The envelope augments the response usage object, so it is emitted only for
// upstream clients that opt in with the metering request header; every other
// client keeps the exact upstream payload.
func AnnotateCodexMetering(payload []byte, reporter *UsageReporter, requested bool) []byte {
	if !requested {
		return payload
	}
	root := gjson.ParseBytes(payload)
	path := "usage"
	if root.Get("response").IsObject() {
		path = "response.usage"
	} else if root.Get("type").Exists() {
		return payload
	}
	m := usage.ParseCodexMetering([]byte(root.Get(path).Raw))
	kind := root.Get("type").String()
	m.Final = kind == "" || kind == "response.completed" || kind == "response.done" || kind == "response.incomplete" || kind == "response.failed"
	if reporter != nil {
		m.AttemptID = reporter.RequestID()
		m.AccountRef = fmt.Sprintf("%x", sha256.Sum256([]byte(reporter.authID)))
	}
	m.Model = root.Get("response.model").String()
	m.ResponseID = root.Get("response.id").String()
	if m.Model == "" {
		m.Model = root.Get("model").String()
	}
	if m.ResponseID == "" {
		m.ResponseID = root.Get("id").String()
	}
	encoded, err := json.Marshal(m)
	if err != nil {
		return payload
	}
	updated, err := sjson.SetRawBytes(payload, path+".codex_metering", encoded)
	if err != nil {
		return payload
	}
	return updated
}

// ObserveCodexUpstreamWork records that an attempt produced billable upstream
// work: generated output or an authoritative usage object. An attempt that only
// returned a rejection has nothing to bill, so failing it over to another
// credential stays safe; an attempt that already generated output does not.
func ObserveCodexUpstreamWork(ctx context.Context, payload []byte) {
	if !HasMeaningfulCodexOutputDelta(payload) {
		root := gjson.ParseBytes(payload)
		if !root.Get("response.usage").IsObject() && !root.Get("usage").IsObject() {
			return
		}
	}
	cliproxyexecutor.MarkUpstreamWork(ctx)
}

func CodexMeteringHeaders(headers http.Header) http.Header {
	result := headers.Clone()
	if result == nil {
		result = make(http.Header)
	}
	result.Set("X-Codex-Metering", "v1")
	return result
}

// CodexMeteringRequested reports whether the caller consumes the versioned
// metering envelope. The proxy only augments response usage for such callers.
func CodexMeteringRequested(ctx context.Context, headers http.Header) bool {
	if headers.Get("X-Codex-Metering") == "v1" {
		return true
	}
	if ginCtx, ok := ctx.Value("gin").(*gin.Context); ok && ginCtx != nil && ginCtx.Request != nil {
		return ginCtx.Request.Header.Get("X-Codex-Metering") == "v1"
	}
	return false
}
