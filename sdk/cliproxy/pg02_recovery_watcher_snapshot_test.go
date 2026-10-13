package cliproxy

import (
	"context"
	"net/http"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/watcher"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
)

// The watcher can retain an unversioned disabled/PREPARED snapshot while the
// management transaction commits. Consume that exact snapshot after commit,
// before the persisted hook, without sleeps or a forced registry refresh.
func TestPG02RecoveryRejectsDelayedWatcherIsolation(t *testing.T) {
	for _, prepared := range []bool{false, true} {
		for _, afterHook := range []bool{false, true} {
			t.Run(map[bool]string{false: "old_disabled", true: "prepared_quarantine"}[prepared], func(t *testing.T) {
				t.Run(map[bool]string{false: "before_hook", true: "after_hook"}[afterHook], func(t *testing.T) {
					f := newPG02CommitFixture(t)
					if r := f.patch(true); r.Code != http.StatusOK {
						t.Fatal(r.Body.String())
					}
					stale, _ := f.m.GetByID(f.id)
					stale.Generation = 0
					if r := f.patch(false); r.Code != http.StatusOK {
						t.Fatal(r.Body.String())
					}
					recovered, _ := f.m.GetByID(f.id)
					if prepared {
						stale = recovered.Clone()
						stale.Generation = 0
						stale.Disabled = true
						stale.Status = coreauth.StatusDisabled
						stale.Metadata["disabled"] = true
						stale.Metadata[coreauth.ManagementDisabledKey] = true
						stale.Metadata[coreauth.RecoveryStateKey] = string(coreauth.ManagementRecoveryPrepared)
					}
					ctx := coreauth.WithSkipPersist(context.Background())
					if afterHook {
						if err := f.s.runtimeAuthSyncHook()(context.Background(), recovered); err != nil {
							t.Fatal(err)
						}
						recovered, _ = f.m.GetByID(f.id)
					}
					f.s.handleAuthUpdate(ctx, watcher.AuthUpdate{Action: watcher.AuthUpdateActionModify, ID: f.id, Auth: stale})
					current, _ := f.m.GetByID(f.id)
					if current.Disabled || coreauth.ManagementIsolation(current) || current.Generation != recovered.Generation {
						t.Fatalf("delayed watcher poisoned committed recovery: before generation=%d after generation=%d disabled=%t isolation=%t", recovered.Generation, current.Generation, current.Disabled, coreauth.ManagementIsolation(current))
					}
					if err := f.s.runtimeAuthSyncHook()(context.Background(), recovered); err != nil {
						t.Fatal(err)
					}
					f.check(t, f.m, false)
					f.restart(t, false)
				})
			})
		}
	}
}

func TestPG02RecoveryWatcherCurrentDiskDisableStillWins(t *testing.T) {
	f := newPG02CommitFixture(t)
	if r := f.patch(true); r.Code != http.StatusOK {
		t.Fatal(r.Body.String())
	}
	if r := f.patch(false); r.Code != http.StatusOK {
		t.Fatal(r.Body.String())
	}
	disabled, _ := f.m.GetByID(f.id)
	disabled.Disabled = true
	disabled.Status = coreauth.StatusDisabled
	disabled.Metadata["disabled"] = true
	disabled.Metadata[coreauth.ManagementDisabledKey] = true
	if _, err := f.store.Save(context.Background(), disabled); err != nil {
		t.Fatal(err)
	}
	disabled.Generation = 0
	f.s.handleAuthUpdate(coreauth.WithSkipPersist(context.Background()), watcher.AuthUpdate{Action: watcher.AuthUpdateActionModify, ID: f.id, Auth: disabled})
	f.check(t, f.m, true)
	f.restart(t, true)
}

func TestPG02RecoveryWatcherUpdateErrorPreservesIdentity(t *testing.T) {
	f := newPG02CommitFixture(t)
	incoming, _ := f.m.GetByID(f.id)
	incoming.Disabled = true
	incoming.Status = coreauth.StatusDisabled
	f.store.fail.Store(true)
	if accepted := f.s.prepareCoreAuthForModelRegistration(context.Background(), incoming); accepted != nil {
		t.Fatal("failed isolated update must not be published")
	}
	current, _ := f.m.GetByID(f.id)
	if !current.Disabled || !coreauth.ManagementIsolation(current) {
		t.Fatal("failed disable must retain its runtime fence")
	}
}
