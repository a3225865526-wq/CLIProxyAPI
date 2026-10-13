package auth

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestP0AuthJSONAtomicReplacement(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "synthetic.json")
	old := []byte(`{"type":"codex","disabled":true,"access_token":"synthetic-unused"}`)
	if err := writeAuthJSONAtomic(path, old); err != nil {
		t.Fatal(err)
	}
	// A process crash during temporary-file writing leaves the committed JSON
	// intact, and the partial sibling must not be discovered as an auth file.
	if err := os.WriteFile(filepath.Join(dir, ".synthetic.json.tmp-interrupted"), []byte(`{"disabled":false`), 0600); err != nil {
		t.Fatal(err)
	}
	store := NewFileTokenStore()
	store.SetBaseDir(dir)
	loaded, err := store.List(context.Background())
	if err != nil || len(loaded) != 1 || !loaded[0].Disabled {
		t.Fatalf("interrupted write reopened auth: %+v %v", loaded, err)
	}
	stop, done := make(chan struct{}), make(chan error, 1)
	go func() {
		for {
			select {
			case <-stop:
				done <- nil
				return
			default:
			}
			data, errRead := os.ReadFile(path)
			if errRead != nil {
				done <- errRead
				return
			}
			var meta map[string]any
			if errParse := json.Unmarshal(data, &meta); errParse != nil {
				done <- errParse
				return
			}
			if _, ok := meta["disabled"].(bool); !ok {
				done <- os.ErrInvalid
				return
			}
		}
	}()
	for i := 0; i < 40; i++ {
		data, errMarshal := json.Marshal(map[string]any{"type": "codex", "disabled": i%2 == 0, "padding": strings.Repeat("x", 8192)})
		if errMarshal != nil {
			t.Fatal(errMarshal)
		}
		if errWrite := writeAuthJSONAtomic(path, data); errWrite != nil {
			close(stop)
			<-done
			t.Fatal(errWrite)
		}
	}
	close(stop)
	if errRead := <-done; errRead != nil {
		t.Fatalf("reader observed partial replacement: %v", errRead)
	}
}

func TestP0AuthJSONFailedReplacementPreservesDestination(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "synthetic.json")
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(path, "committed")
	if err := os.WriteFile(marker, []byte("preserve"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := writeAuthJSONAtomic(path, []byte(`{"disabled":false}`)); err == nil {
		t.Fatal("replacement unexpectedly succeeded")
	}
	data, err := os.ReadFile(marker)
	if err != nil || string(data) != "preserve" {
		t.Fatalf("committed destination changed: %q %v", data, err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 1 {
		t.Fatalf("temporary files leaked: %+v %v", entries, err)
	}
}
