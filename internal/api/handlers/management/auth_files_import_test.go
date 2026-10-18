package management

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
)

func poolImportRequest(t *testing.T, handler *Handler, name, content string) *httptest.ResponseRecorder {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"name": name, "content": base64.StdEncoding.EncodeToString([]byte(content))})
	rec := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(rec)
	ctx.Request = httptest.NewRequest(http.MethodPost, "/v0/management/pool/import", bytes.NewReader(body))
	ctx.Request.Header.Set("Content-Type", "application/json")
	handler.ImportCredentialAtomic(ctx)
	return rec
}

func TestImportCredentialAtomicStoresAndReportsDigest(t *testing.T) {
	t.Setenv("MANAGEMENT_PASSWORD", "")
	dir := t.TempDir()
	manager := coreauth.NewManager(nil, nil, nil)
	h := NewHandlerWithoutConfigFilePath(&config.Config{AuthDir: dir}, manager)
	content := `{"type":"codex","account_id":"synthetic-account","chatgpt_account_id":"synthetic-account","email":"synthetic@example.com","plan_type":"plus","access_token":"synthetic-access","refresh_token":"synthetic-refresh","id_token":"synthetic-id"}`
	rec := poolImportRequest(t, h, "codex-synthetic.json", content)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var payload map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if payload["credential_ref"] != "codex-synthetic.json" || payload["credential_digest"] == "" || payload["provider"] != "codex" {
		t.Fatalf("unexpected payload: %#v", payload)
	}
	if strings.Contains(rec.Body.String(), "synthetic-access") || strings.Contains(rec.Body.String(), "synthetic-refresh") {
		t.Fatal("response leaked token material")
	}
	stored, err := os.ReadFile(filepath.Join(dir, "codex-synthetic.json"))
	if err != nil {
		t.Fatalf("read stored credential: %v", err)
	}
	var storedMetadata map[string]any
	if err := json.Unmarshal(stored, &storedMetadata); err != nil {
		t.Fatalf("stored credential is not JSON: %v", err)
	}
	if storedMetadata["disabled"] != true || storedMetadata["management_disabled"] != true {
		t.Fatalf("imported credential is not durably isolated: %#v", storedMetadata)
	}
	if storedMetadata["access_token"] != "synthetic-access" || storedMetadata["refresh_token"] != "synthetic-refresh" {
		t.Fatal("stored credential token fields changed")
	}
	info, err := os.Stat(filepath.Join(dir, "codex-synthetic.json"))
	if err != nil || info.Mode().Perm()&0077 != 0 {
		t.Fatalf("credential permissions are not private: %v %v", info.Mode().Perm(), err)
	}
}

func TestImportCredentialAtomicRejectsInvalidWithoutFile(t *testing.T) {
	t.Setenv("MANAGEMENT_PASSWORD", "")
	dir := t.TempDir()
	manager := coreauth.NewManager(nil, nil, nil)
	h := NewHandlerWithoutConfigFilePath(&config.Config{AuthDir: dir}, manager)
	rec := poolImportRequest(t, h, "codex-invalid.json", `{"type":"codex","access_token":"x"}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status=%d", rec.Code)
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 0 {
		t.Fatal("invalid import left a file")
	}
}
