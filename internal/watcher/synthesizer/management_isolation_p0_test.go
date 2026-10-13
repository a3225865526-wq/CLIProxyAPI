package synthesizer

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
)

func TestFileSynthesizerManagementIsolationP0(t *testing.T) {
	for _, tc := range []struct {
		name     string
		raw      string
		isolated bool
	}{
		{"legacy", `{"type":"codex","disabled":true}`, true},
		{"contradictory", `{"type":"codex","disabled":false,"management_disabled":true}`, true},
		{"malformed", `{"type":"codex","disabled":false,"management_disabled":"false"}`, true},
		{"missing-management-flag", `{"type":"codex","disabled":false}`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			if errWrite := os.WriteFile(filepath.Join(dir, "synthetic.json"), []byte(tc.raw), 0600); errWrite != nil {
				t.Fatal(errWrite)
			}
			auths, errSynthesize := NewFileSynthesizer().Synthesize(&SynthesisContext{AuthDir: dir, Now: time.Now()})
			if errSynthesize != nil || len(auths) != 1 {
				t.Fatalf("synthesis: %v %d", errSynthesize, len(auths))
			}
			if auths[0].Disabled != tc.isolated || coreauth.ManagementIsolation(auths[0]) != tc.isolated {
				t.Fatal("watcher admitted isolated persistent state")
			}
		})
	}
}
