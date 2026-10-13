package management

import (
	"context"
	"encoding/json"
	"os"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	sdkAuth "github.com/router-for-me/CLIProxyAPI/v8/sdk/auth"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
)

type poolFirstSaveStorage struct {
	metadata    map[string]any
	sawDisabled bool
}

func (store *poolFirstSaveStorage) SetMetadata(metadata map[string]any) { store.metadata = metadata }
func (store *poolFirstSaveStorage) SaveTokenToFile(path string) error {
	store.sawDisabled = store.metadata["disabled"] == true
	body, err := json.Marshal(store.metadata)
	if err != nil {
		return err
	}
	return os.WriteFile(path, body, 0600)
}

func TestPoolGuardAuthorizationFirstSaveDisabled(t *testing.T) {
	t.Setenv("CLEARAPI_POOL_ROLE", "staging")
	cfg := &config.Config{AuthDir: t.TempDir()}
	manager := coreauth.NewManager(nil, nil, nil)
	manager.SetConfig(cfg)
	h := NewHandler(cfg, "", manager)
	h.tokenStore = sdkAuth.NewFileTokenStore()
	store := &poolFirstSaveStorage{}
	auth := &coreauth.Auth{ID: "synthetic-codex.json", Provider: "codex", FileName: "synthetic-codex.json", Storage: store, Metadata: map[string]any{"type": "codex", "access_token": "synthetic-unused"}}
	h.SetPostAuthHook(func(_ context.Context, auth *coreauth.Auth) error { auth.Disabled = false; return nil })
	path, err := h.saveTokenRecord(context.Background(), auth)
	if err != nil {
		t.Fatal(err)
	}
	if path == "" || !store.sawDisabled || !auth.Disabled {
		t.Fatal("first persisted credential was not disabled")
	}
}

func TestPoolGuardServiceCannotSaveAuthorization(t *testing.T) {
	t.Setenv("CLEARAPI_POOL_ROLE", "service")
	cfg := &config.Config{AuthDir: t.TempDir()}
	manager := coreauth.NewManager(nil, nil, nil)
	manager.SetConfig(cfg)
	h := NewHandler(cfg, "", manager)
	auth := &coreauth.Auth{ID: "synthetic-codex.json", Provider: "codex", FileName: "synthetic-codex.json", Metadata: map[string]any{"pool_admitted": true}}
	if _, err := h.saveTokenRecord(context.Background(), auth); err == nil {
		t.Fatal("service authorization save accepted")
	}
	files, err := os.ReadDir(cfg.AuthDir)
	if err != nil || len(files) != 0 {
		t.Fatal("service authorization wrote a credential")
	}
}
