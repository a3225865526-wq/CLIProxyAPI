package auth

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"

	internalconfig "github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
)

func TestPoolGuardCheckpointActualProcessRestartRejectsReplay(t *testing.T) {
	m, probe, _, file, first := poolGuardFixture(t, "service")
	revoked := first
	revoked.Revision++
	revoked.Grants = nil
	writePoolGrant(t, file, revoked)
	_, err := m.Execute(context.Background(), []string{"codex"}, cliproxyexecutor.Request{Model: "synthetic-native"}, cliproxyexecutor.Options{})
	if err == nil || probe.calls.Load() != 0 {
		t.Fatal("revoked manifest executed")
	}
	writePoolGrant(t, file, first)
	child := exec.Command(os.Args[0], "-test.run=^TestPoolGuardCheckpointReplayChild$", "-test.count=1")
	child.Env = []string{
		"POOL_SYNTHETIC_REPLAY_CHILD=1", "CLEARAPI_POOL_ROLE=service",
		"CLEARAPI_POOL_EXECUTOR_ID=" + m.poolGuard.executorID,
		"CLEARAPI_POOL_ADMISSION_FILE=" + file,
		"CLEARAPI_POOL_CHECKPOINT_FILE=" + m.poolGuard.checkpoint,
		"POOL_SYNTHETIC_AUTH_DIR=" + m.runtimeConfigSnapshot().AuthDir,
	}
	output, err := child.CombinedOutput()
	if err != nil {
		t.Fatalf("isolated replay child failed: %v %s", err, output)
	}
}

func TestPoolGuardCheckpointReplayChild(t *testing.T) {
	if os.Getenv("POOL_SYNTHETIC_REPLAY_CHILD") != "1" {
		t.Skip("subprocess-only synthetic replay probe")
	}
	m := NewManager(nil, nil, nil)
	m.SetConfig(&internalconfig.Config{AuthDir: os.Getenv("POOL_SYNTHETIC_AUTH_DIR")})
	if _, err := m.poolGrants(); err == nil {
		t.Fatal("old grant accepted after process restart")
	}
	probe := &poolProbeExecutor{}
	m.RegisterExecutor(probe)
	auth := &Auth{ID: "synthetic-pool-account", Provider: "codex", Status: StatusActive, Attributes: map[string]string{AttributeAuthKind: AuthKindOAuth}, Metadata: map[string]any{"access_token": "synthetic-unused"}}
	registered, err := m.Register(context.Background(), auth)
	if err != nil || !registered.Disabled {
		t.Fatal("replayed account was not quarantined")
	}
	_, err = m.Execute(context.Background(), []string{"codex"}, cliproxyexecutor.Request{Model: "synthetic-native"}, cliproxyexecutor.Options{})
	if err == nil || probe.calls.Load() != 0 {
		t.Fatal("process restart invoked synthetic upstream")
	}
}

func TestPoolGuardCheckpointRejectsDamageAndIdentityMismatch(t *testing.T) {
	for _, scenario := range []string{"missing", "corrupt", "torn", "wrong-instance", "inside-auth-dir", "same-revision-change", "directory", "missing-config", "old-protocol"} {
		t.Run(scenario, func(t *testing.T) {
			m, probe, _, file, record := poolGuardFixture(t, "service")
			switch scenario {
			case "missing":
				m.poolGuard.checkpoint = filepath.Join(t.TempDir(), "not-provisioned")
			case "corrupt":
				if err := os.WriteFile(m.poolGuard.checkpoint, []byte("{}\n"), 0600); err != nil {
					t.Fatal(err)
				}
			case "torn":
				journal, err := os.OpenFile(m.poolGuard.checkpoint, os.O_APPEND|os.O_WRONLY, 0)
				if err != nil {
					t.Fatal(err)
				}
				if _, err = journal.WriteString("{\"revision\":"); err != nil {
					t.Fatal(err)
				}
				if err = journal.Close(); err != nil {
					t.Fatal(err)
				}
			case "wrong-instance":
				record.ExecutorID = "other-synthetic-executor"
				writePoolGrant(t, file, record)
			case "inside-auth-dir":
				m.poolGuard.checkpoint = filepath.Join(m.runtimeConfigSnapshot().AuthDir, "checkpoint.jsonl")
				if err := ProvisionPoolCheckpoint(m.poolGuard.checkpoint, record.ExecutorID); err != nil {
					t.Fatal(err)
				}
			case "same-revision-change":
				record.Grants[0].MaxConcurrency = 2
				writePoolGrant(t, file, record)
			case "directory":
				m.poolGuard.checkpoint = t.TempDir()
			case "missing-config":
				m.poolGuard.checkpoint = ""
			case "old-protocol":
				record.GuardVersion = 1
				writePoolGrant(t, file, record)
			}
			_, err := m.Execute(context.Background(), []string{"codex"}, cliproxyexecutor.Request{Model: "synthetic-native"}, cliproxyexecutor.Options{})
			if err == nil || probe.calls.Load() != 0 {
				t.Fatal("unsafe checkpoint invoked upstream")
			}
		})
	}
}

func TestPoolGuardCheckpointNewRevisionAndConcurrentManagers(t *testing.T) {
	m, probe, _, file, record := poolGuardFixture(t, "service")
	if err := ProvisionPoolCheckpoint(m.poolGuard.checkpoint, record.ExecutorID); err == nil {
		t.Fatal("checkpoint reset was allowed")
	}
	record.Revision++
	writePoolGrant(t, file, record)
	var group sync.WaitGroup
	errors := make(chan error, 2)
	for range 2 {
		group.Go(func() {
			other := NewManager(nil, nil, nil)
			other.SetConfig(m.runtimeConfigSnapshot())
			_, err := other.poolGrants()
			errors <- err
		})
	}
	group.Wait()
	close(errors)
	successes := 0
	for err := range errors {
		if err == nil {
			successes++
		}
	}
	if successes == 0 {
		t.Fatal("no manager durably accepted the new revision")
	}
	restarted := NewManager(nil, nil, nil)
	restarted.SetConfig(m.runtimeConfigSnapshot())
	accepted, err := restarted.poolGrants()
	if err != nil || accepted.Revision != record.Revision {
		t.Fatal("concurrent journal was corrupted")
	}
	_, err = m.Execute(context.Background(), []string{"codex"}, cliproxyexecutor.Request{Model: "synthetic-native"}, cliproxyexecutor.Options{})
	if err != nil || probe.calls.Load() != 1 {
		t.Fatal("unchanged admitted credential failed")
	}
}

func TestPoolGuardCheckpointUnavailablePersistenceNeverCallsUpstream(t *testing.T) {
	m, probe, _, file, record := poolGuardFixture(t, "service")
	journal, err := os.OpenFile(m.poolGuard.checkpoint, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := journal.Close(); err != nil {
			t.Error(err)
		}
	}()
	if err = lockPoolCheckpoint(journal); err != nil {
		t.Fatal(err)
	}
	record.Revision++
	writePoolGrant(t, file, record)
	_, err = m.Execute(context.Background(), []string{"codex"}, cliproxyexecutor.Request{Model: "synthetic-native"}, cliproxyexecutor.Options{})
	unlockPoolCheckpoint(journal)
	if err == nil || probe.calls.Load() != 0 {
		t.Fatal("request executed without a durable revision")
	}
	_, err = m.Execute(context.Background(), []string{"codex"}, cliproxyexecutor.Request{Model: "synthetic-native"}, cliproxyexecutor.Options{})
	if err != nil || probe.calls.Load() != 1 {
		t.Fatal("request did not recover after checkpoint became available")
	}
}
