package auth

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
)

func TestFileManagementIsolationP0ReadCompatibility(t *testing.T) {
	for _, tc := range []struct {
		name, raw string
		isolated  bool
	}{
		{"legacy-disabled", `{"type":"codex","disabled":true}`, true},
		{"legacy-enabled", `{"type":"codex","disabled":false}`, false},
		{"missing-disabled", `{"type":"codex"}`, false},
		{"contradictory", `{"type":"codex","disabled":false,"management_disabled":true}`, true},
		{"malformed", `{"type":"codex","disabled":false,"management_disabled":"false"}`, true},
		{"null", `{"type":"codex","disabled":false,"management_disabled":null}`, true},
		{"pending", `{"type":"codex","disabled":true,"management_disabled":false}`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			if errWrite := os.WriteFile(filepath.Join(dir, "synthetic.json"), []byte(tc.raw), 0600); errWrite != nil {
				t.Fatal(errWrite)
			}
			store := NewFileTokenStore()
			store.SetBaseDir(dir)
			items, errList := store.List(context.Background())
			if errList != nil || len(items) != 1 {
				t.Fatalf("list: %v %d", errList, len(items))
			}
			if coreauth.ManagementIsolation(items[0]) != tc.isolated {
				t.Fatal("legacy migration mismatch")
			}
			if tc.isolated && !items[0].Disabled {
				t.Fatal("load granted contradictory eligibility")
			}
		})
	}
}

func TestFileManagementIsolationP0DurabilityConfirmation(t *testing.T) {
	dir := t.TempDir()
	store := NewFileTokenStore()
	store.SetBaseDir(dir)
	a := &coreauth.Auth{ID: "synthetic.json", Provider: "codex", Disabled: true, Metadata: map[string]any{"type": "codex", "account_id": "synthetic", coreauth.ManagementDisabledKey: true}}
	if _, errSave := store.Save(coreauth.WithAuthCreationIntent(context.Background()), a); errSave != nil {
		t.Fatal(errSave)
	}
	errConfirm := store.ConfirmManagementDisable(context.Background(), a)
	if runtime.GOOS == "linux" {
		if errConfirm != nil {
			t.Fatal(errConfirm)
		}
	} else if errConfirm == nil {
		t.Fatal("unqualified platform reported durable management success")
	}
	a.Metadata[coreauth.ManagementDisabledKey] = false
	if _, errSave := store.Save(context.Background(), a); errSave != nil {
		t.Fatal(errSave)
	}
	if errMismatch := store.ConfirmManagementDisable(context.Background(), a); errMismatch == nil {
		t.Fatal("missing management isolation confirmed")
	}
}
