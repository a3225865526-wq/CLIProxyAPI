package helps

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/usage"
	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
)

// AnnotateCodexMetering runs before protocol conversion/default synthesis.
// Only response objects carry the extension; delta counters are not usage.
func AnnotateCodexMetering(payload []byte, reporter *UsageReporter) []byte {
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

func CodexMeteringHeaders(headers http.Header) http.Header {
	result := headers.Clone()
	if result == nil {
		result = make(http.Header)
	}
	result.Set("X-Codex-Metering", "v1")
	return result
}
