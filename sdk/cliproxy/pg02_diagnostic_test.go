package cliproxy

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	filestore "github.com/router-for-me/CLIProxyAPI/v8/sdk/auth"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
)

// Diagnostic test to verify fail-closed behavior
func TestPG02FailClosedDiagnostic(t *testing.T) {
	t.Setenv("CLEARAPI_POOL_ROLE", "service")
	ctx := context.Background()
	dir := t.TempDir()

	store := filestore.NewFileTokenStore()
	store.SetBaseDir(dir)

	// Test 1: File with explicit disabled=false should load as enabled
	t.Run("explicit_false", func(t *testing.T) {
		path := filepath.Join(dir, "test1.json")
		data := map[string]any{"type": "codex", "disabled": false, "access_token": "test"}
		raw, _ := json.Marshal(data)
		os.WriteFile(path, raw, 0600)

		auths, err := store.List(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if len(auths) != 1 {
			t.Fatalf("expected 1 auth, got %d", len(auths))
		}
		if auths[0].Disabled {
			t.Error("explicit disabled=false loaded as Disabled=true")
		}
		t.Logf("✓ explicit disabled=false → Disabled=%v", auths[0].Disabled)
	})

	// Test 2: File without disabled field should load as disabled (fail-closed)
	t.Run("missing_disabled", func(t *testing.T) {
		os.RemoveAll(dir)
		os.MkdirAll(dir, 0700)
		store.SetBaseDir(dir)

		path := filepath.Join(dir, "test2.json")
		data := map[string]any{"type": "codex", "access_token": "test"}
		raw, _ := json.Marshal(data)
		os.WriteFile(path, raw, 0600)

		auths, err := store.List(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if len(auths) != 1 {
			t.Fatalf("expected 1 auth, got %d", len(auths))
		}
		if !auths[0].Disabled {
			t.Error("missing disabled field loaded as Disabled=false (SECURITY FAILURE)")
		}
		t.Logf("✓ missing disabled field → Disabled=%v (fail-closed)", auths[0].Disabled)
	})

	// Test 3: Save with Disabled=false should write disabled=false to file
	t.Run("save_disabled_false", func(t *testing.T) {
		os.RemoveAll(dir)
		os.MkdirAll(dir, 0700)
		store.SetBaseDir(dir)

		auth := &coreauth.Auth{
			ID:       "test3.json",
			FileName: "test3.json",
			Provider: "codex",
			Disabled: false,
			Status:   coreauth.StatusActive,
			Metadata: map[string]any{"type": "codex", "access_token": "test"},
		}

		path, err := store.Save(ctx, auth)
		if err != nil {
			t.Fatal(err)
		}

		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}

		var data map[string]any
		json.Unmarshal(raw, &data)

		disabled, ok := data["disabled"].(bool)
		if !ok {
			t.Error("disabled field not present in saved file")
		}
		if disabled {
			t.Error("saved Disabled=false but file has disabled=true")
		}
		t.Logf("✓ Save(Disabled=false) → file contains disabled=%v", disabled)

		// Verify reload
		auths, err := store.List(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if len(auths) != 1 || auths[0].Disabled {
			t.Error("reloaded auth is disabled despite disabled=false in file")
		}
		t.Logf("✓ Reload → Disabled=%v", auths[0].Disabled)
	})
}
