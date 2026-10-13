package cliproxy
import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	filestore "github.com/router-for-me/CLIProxyAPI/v8/sdk/auth"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/config"
)
func TestPG02VerifyFileContent(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "auths")
	os.Mkdir(dir, 0700)
	authFile := "test.json"
	authPath := filepath.Join(dir, authFile)
	metadata := map[string]any{
		"type": "codex",
		"disabled": false,
	}
	metaBody, _ := json.Marshal(metadata)
	os.WriteFile(authPath, metaBody, 0600)
	
	// Read back raw
	raw, _ := os.ReadFile(authPath)
	t.Logf("File content: %s", string(raw))
	
	var check map[string]any
	json.Unmarshal(raw, &check)
	disabledInFile, _ := check["disabled"].(bool)
	t.Logf("File disabled field: %v (type: %T)", check["disabled"], check["disabled"])
	
	// Load via FileTokenStore
	cfg := &config.Config{AuthDir: dir}
	store := filestore.NewFileTokenStore()
	store.SetBaseDir(dir)
	m := coreauth.NewManager(store, nil, nil)
	m.SetConfig(cfg)
	m.Load(context.Background())
	
	a, ok := m.GetByID(authFile)
	if ok {
		t.Logf("Loaded auth Disabled: %v", a.Disabled)
	}
	
	if !disabledInFile && a != nil && a.Disabled {
		t.Errorf("BUG: File has disabled=false, but loaded as Disabled=true")
	}
}
