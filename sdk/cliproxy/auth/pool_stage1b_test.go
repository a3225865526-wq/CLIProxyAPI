package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	internalconfig "github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
)

type poolFailingStore struct{}

func (poolFailingStore) List(context.Context) ([]*Auth, error) { return nil, nil }
func (poolFailingStore) Save(context.Context, *Auth) (string, error) {
	return "", errors.New("synthetic store failure")
}
func (poolFailingStore) Delete(context.Context, string) error { return nil }

func TestPoolStage1BPromotionCredentialStoreFailure(t *testing.T) {
	m, probe, _, file, record := poolGuardFixture(t, "service")
	record.Revision++
	writePoolGrant(t, file, record)
	revision, identity := poolExpectation(t, m)
	m.SetStore(poolFailingStore{})
	if err := m.PromotePoolIdentities(context.Background(), PoolPromotion{ExpectedRevision: revision, Identities: []PoolIdentityExpectation{identity}}); err == nil {
		t.Fatal("store failure promoted")
	}
	if poolRequest(m) == nil || probe.calls.Load() != 0 {
		t.Fatal("store failure opened router")
	}
}

func TestPoolStage1BActualProcessTrustRecovery(t *testing.T) {
	for _, state := range []string{"trusted", "revoked"} {
		t.Run(state, func(t *testing.T) {
			m, _, _, file, _ := poolGuardFixture(t, "service")
			if state == "revoked" {
				poolRevoke(t, m)
			}
			child := exec.Command(os.Args[0], "-test.run=^TestPoolStage1BRecoveryChild$", "-test.count=1")
			child.Env = []string{"POOL_STAGE1B_CHILD=" + state, "CLEARAPI_POOL_ROLE=service", "CLEARAPI_POOL_EXECUTOR_ID=" + m.poolGuard.executorID, "CLEARAPI_POOL_CHECKPOINT_FILE=" + m.poolGuard.checkpoint, "CLEARAPI_POOL_ADMISSION_FILE=" + file, "POOL_SYNTHETIC_AUTH_DIR=" + m.runtimeConfigSnapshot().AuthDir}
			if output, err := child.CombinedOutput(); err != nil {
				t.Fatalf("new process recovery failed: %v %s", err, output)
			}
		})
	}
}

func TestPoolStage1BRecoveryChild(t *testing.T) {
	state := os.Getenv("POOL_STAGE1B_CHILD")
	if state == "" {
		t.Skip("synthetic subprocess only")
	}
	m := NewManager(nil, nil, nil)
	m.SetConfig(&internalconfig.Config{AuthDir: os.Getenv("POOL_SYNTHETIC_AUTH_DIR")})
	probe := &poolProbeExecutor{}
	m.RegisterExecutor(probe)
	auth := &Auth{ID: "synthetic-pool-account", Provider: "codex", FileName: "synthetic-pool-account.json", Status: StatusActive, Attributes: map[string]string{AttributeAuthKind: AuthKindOAuth}, Metadata: map[string]any{"access_token": "synthetic-unused", "account_id": "synthetic-account-id", "email": "synthetic-pool-account@staging.invalid"}}
	if _, err := m.Register(context.Background(), auth); err != nil {
		t.Fatal(err)
	}
	registry.GetGlobalRegistry().RegisterClient(auth.ID, auth.Provider, []*registry.ModelInfo{{ID: "synthetic-native"}})
	err := poolRequest(m)
	if state == "trusted" {
		if err != nil || probe.calls.Load() != 1 {
			t.Fatal("trusted process failed", err)
		}
	} else if err == nil || probe.calls.Load() != 0 {
		t.Fatal("revoked process revived")
	}
}

type poolPreDispatchFailure struct {
	poolProbeExecutor
	attempts atomic.Int32
}

func (probe *poolPreDispatchFailure) Execute(ctx context.Context, auth *Auth, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
	if probe.attempts.Add(1) == 1 {
		return cliproxyexecutor.Response{}, &Error{HTTPStatus: 500, Message: "synthetic local preparation failure"}
	}
	return probe.poolProbeExecutor.Execute(ctx, auth, req, opts)
}

func TestPoolStage1BPreDispatchSafeFallback(t *testing.T) {
	m, _, auth, file, record := poolGuardFixture(t, "service")
	second := auth.Clone()
	second.ID = "synthetic-second"
	second.FileName = "synthetic-second.json"
	grant := record.Grants[0]
	grant.AuthID = second.ID
	grant.CredentialDigest = PoolCredentialDigest(second)
	record.Grants = append(record.Grants, grant)
	record.Revision++
	writePoolGrant(t, file, record)
	if _, err := m.Register(context.Background(), second); err != nil {
		t.Fatal(err)
	}
	revision, identity := poolExpectation(t, m)
	if err := m.PromotePoolIdentities(context.Background(), PoolPromotion{ExpectedRevision: revision, Identities: []PoolIdentityExpectation{identity, {AuthID: second.ID, Provider: second.Provider, CredentialDigest: PoolCredentialDigest(second)}}}); err != nil {
		t.Fatal(err)
	}
	first, _ := m.GetByID(identity.AuthID)
	secondRegistered, _ := m.GetByID(second.ID)
	if err := grantPoolModelCapability(t, m, first, "synthetic-native"); err != nil {
		t.Fatal(err)
	}
	if err := grantPoolModelCapability(t, m, secondRegistered, "synthetic-native"); err != nil {
		t.Fatal(err)
	}
	registry.GetGlobalRegistry().RegisterClient(second.ID, second.Provider, []*registry.ModelInfo{{ID: "synthetic-native"}})
	defer registry.GetGlobalRegistry().UnregisterClient(second.ID)
	probe := &poolPreDispatchFailure{}
	m.RegisterExecutor(probe)
	if err := poolRequest(m); err != nil || probe.attempts.Load() != 2 || probe.calls.Load() != 1 {
		t.Fatal("safe pre-dispatch fallback failed", err)
	}
}

func poolExpectation(t *testing.T, m *Manager) (uint64, PoolIdentityExpectation) {
	t.Helper()
	revision, states, err := m.PoolTrustSnapshot()
	if err != nil {
		t.Fatal(err)
	}
	auth, _ := m.GetByID("synthetic-pool-account")
	identity := PoolIdentityExpectation{AuthID: auth.ID, Provider: auth.Provider, CredentialDigest: PoolCredentialDigest(auth)}
	for _, state := range states {
		if state.AuthID == auth.ID {
			identity.Generation = state.Generation
		}
	}
	return revision, identity
}

func explicitPoolPromotion(t *testing.T, m *Manager) {
	t.Helper()
	revision, identity := poolExpectation(t, m)
	if err := m.PromotePoolIdentities(context.Background(), PoolPromotion{ExpectedRevision: revision, Identities: []PoolIdentityExpectation{identity}}); err != nil {
		t.Fatal(err)
	}
	auth, _ := m.GetByID(identity.AuthID)
	if auth == nil {
		t.Fatal("promoted identity vanished")
	}
	if err := grantPoolModelCapability(t, m, auth, "synthetic-native"); err != nil {
		t.Fatal(err)
	}
}

func poolRevoke(t *testing.T, m *Manager) {
	t.Helper()
	revision, identity := poolExpectation(t, m)
	if err := m.RevokePoolIdentity(context.Background(), PoolRevocation{ExpectedRevision: revision, Identity: identity}); err != nil {
		t.Fatal(err)
	}
}

func poolRequest(m *Manager) error {
	_, err := m.Execute(context.Background(), []string{"codex"}, cliproxyexecutor.Request{Model: "synthetic-native"}, cliproxyexecutor.Options{})
	return err
}

func waitPoolSignal(t *testing.T, ch <-chan struct{}) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(3 * time.Second):
		t.Fatal("synthetic lifecycle did not finish")
	}
}

func TestPoolStage1BPendingRequiresExplicitPromotion(t *testing.T) {
	m, probe, _, file, record := poolGuardFixture(t, "service")
	record.Revision++
	writePoolGrant(t, file, record)
	if err := poolRequest(m); err == nil || probe.calls.Load() != 0 {
		t.Fatal("policy update automatically trusted")
	}
	explicitPoolPromotion(t, m)
	if err := poolRequest(m); err != nil || probe.calls.Load() != 1 {
		t.Fatal("explicit promotion failed", err)
	}
}

func TestPoolStage1BPromotionCAS(t *testing.T) {
	for _, scenario := range []string{"digest", "provider", "auth-version", "generation", "duplicate", "duplicate-identity", "persistence"} {
		t.Run(scenario, func(t *testing.T) {
			m, probe, _, file, record := poolGuardFixture(t, "service")
			record.Revision++
			writePoolGrant(t, file, record)
			revision, identity := poolExpectation(t, m)
			command := PoolPromotion{ExpectedRevision: revision, Identities: []PoolIdentityExpectation{identity}}
			switch scenario {
			case "digest":
				command.Identities[0].CredentialDigest = "different"
			case "provider":
				command.Identities[0].Provider = "other"
			case "auth-version":
				command.ExpectedRevision--
			case "generation":
				command.Identities[0].Generation--
			case "duplicate":
				explicitPoolPromotion(t, m)
			case "duplicate-identity":
				command.Identities = append(command.Identities, identity)
			case "persistence":
				file, err := os.OpenFile(m.poolGuard.checkpoint, os.O_RDWR, 0)
				if err != nil {
					t.Fatal(err)
				}
				if err := lockPoolCheckpoint(file); err != nil {
					t.Fatal(err)
				}
				defer func() { unlockPoolCheckpoint(file); file.Close() }()
			}
			if err := m.PromotePoolIdentities(context.Background(), command); err == nil {
				t.Fatal("unsafe promotion accepted")
			}
			if scenario != "duplicate" && poolRequest(m) == nil {
				t.Fatal("rejected promotion routed")
			}
			if probe.calls.Load() != 0 {
				t.Fatal("rejected promotion called upstream")
			}
		})
	}
}

func TestPoolStage1BRevokedCannotRecover(t *testing.T) {
	for _, scenario := range []string{"router", "health", "reload", "restart", "stale-promotion", "duplicate-revoke", "fresh-promotion"} {
		t.Run(scenario, func(t *testing.T) {
			m, probe, auth, _, _ := poolGuardFixture(t, "service")
			oldRevision, oldIdentity := poolExpectation(t, m)
			poolRevoke(t, m)
			switch scenario {
			case "health":
				auth.Status = StatusActive
				auth.Unavailable = false
				auth.Disabled = false
				if _, err := m.Update(context.Background(), auth); err != nil {
					t.Fatal(err)
				}
			case "reload":
				if _, err := m.Register(context.Background(), auth); err != nil {
					t.Fatal(err)
				}
			case "restart":
				restarted := NewManager(nil, nil, nil)
				restarted.SetConfig(m.runtimeConfigSnapshot())
				restarted.RegisterExecutor(probe)
				if _, err := restarted.Register(context.Background(), auth); err != nil {
					t.Fatal(err)
				}
				m = restarted
			case "stale-promotion":
				if err := m.PromotePoolIdentities(context.Background(), PoolPromotion{ExpectedRevision: oldRevision, Identities: []PoolIdentityExpectation{oldIdentity}}); err == nil {
					t.Fatal("stale promotion revived")
				}
			case "duplicate-revoke":
				if err := m.RevokePoolIdentity(context.Background(), PoolRevocation{ExpectedRevision: oldRevision, Identity: oldIdentity}); err == nil {
					t.Fatal("duplicate old revoke was not rejected")
				}
			case "fresh-promotion":
				explicitPoolPromotion(t, m)
			}
			if scenario == "fresh-promotion" {
				if poolRequest(m) != nil {
					t.Fatal("new legal promotion failed")
				}
				return
			}
			if poolRequest(m) == nil || probe.calls.Load() != 0 {
				t.Fatal("revoked identity revived")
			}
			_, states, err := m.PoolTrustSnapshot()
			if err != nil || len(states) != 1 || states[0].State != PoolTrustRevoked {
				t.Fatal("revoke record disappeared", err, states)
			}
		})
	}
}

func TestPoolStage1BRevokePersistenceFailureKeepsCommittedState(t *testing.T) {
	m, probe, _, _, _ := poolGuardFixture(t, "service")
	revision, identity := poolExpectation(t, m)
	file, err := os.OpenFile(m.poolGuard.checkpoint, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := lockPoolCheckpoint(file); err != nil {
		t.Fatal(err)
	}
	err = m.RevokePoolIdentity(context.Background(), PoolRevocation{ExpectedRevision: revision, Identity: identity})
	unlockPoolCheckpoint(file)
	file.Close()
	if err == nil {
		t.Fatal("failed persistence reported revoke success")
	}
	next, states, err := m.PoolTrustSnapshot()
	if err != nil || next != revision || states[0].State != PoolTrustTrusted {
		t.Fatal("failure split state", err)
	}
	if poolRequest(m) != nil || probe.calls.Load() != 1 {
		t.Fatal("failed revoke silently changed committed authority")
	}
}

func TestPoolStage1BCredentialReplacementBurnsOldTrust(t *testing.T) {
	m, probe, auth, _, _ := poolGuardFixture(t, "service")
	revision, identity := poolExpectation(t, m)
	// Replacing the stable account identity is a credential replacement even
	// when the auth ID and file name stay the same; restoring the old identity
	// bytes afterwards must not revive the burned trust.
	replacement := auth.Clone()
	replacement.Metadata["account_id"] = "synthetic-account-id-replaced"
	if _, err := m.Update(context.Background(), replacement); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Update(context.Background(), auth); err != nil {
		t.Fatal(err)
	}
	if poolRequest(m) == nil || probe.calls.Load() != 0 {
		t.Fatal("old credential bytes restored old trust")
	}
	if err := m.PromotePoolIdentities(context.Background(), PoolPromotion{ExpectedRevision: revision, Identities: []PoolIdentityExpectation{identity}}); err == nil {
		t.Fatal("stale identity promotion accepted")
	}
}

func TestPoolStage1BConcurrentPromotionReplacementAndRevoke(t *testing.T) {
	for _, scenario := range []string{"replace", "revoke"} {
		t.Run(scenario, func(t *testing.T) {
			m, probe, auth, _, _ := poolGuardFixture(t, "service")
			revision, identity := poolExpectation(t, m)
			start := make(chan struct{})
			var group sync.WaitGroup
			group.Go(func() {
				<-start
				_ = m.PromotePoolIdentities(context.Background(), PoolPromotion{ExpectedRevision: revision, Identities: []PoolIdentityExpectation{identity}})
			})
			group.Go(func() {
				<-start
					if scenario == "replace" {
						auth.Metadata["account_id"] = "synthetic-account-id-replaced"
						_, _ = m.Update(context.Background(), auth)
					} else {
					// A stale revoke may lose CAS. A fresh security revoke must then win.
					_ = m.RevokePoolIdentity(context.Background(), PoolRevocation{ExpectedRevision: revision, Identity: identity})
				}
			})
			close(start)
			group.Wait()
			if scenario == "revoke" {
				poolRevoke(t, m)
			}
			if poolRequest(m) == nil || probe.calls.Load() != 0 {
				t.Fatal("concurrent mutation retained trust")
			}
		})
	}
}

type stage1BProbe struct {
	poolProbeExecutor
	entered         chan struct{}
	permit          <-chan struct{}
	sent            chan struct{}
	finished        chan struct{}
	complete        <-chan struct{}
	panicBefore     bool
	upstreamFailure bool
}

func (probe *stage1BProbe) Execute(ctx context.Context, _ *Auth, _ cliproxyexecutor.Request, _ cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
	defer close(probe.finished)
	close(probe.entered)
	if probe.panicBefore {
		panic("synthetic")
	}
	if probe.permit != nil {
		<-probe.permit
	}
	if err := cliproxyexecutor.BeforeUpstreamDispatch(ctx); err != nil {
		return cliproxyexecutor.Response{}, err
	}
	probe.calls.Add(1)
	close(probe.sent)
	select {
	case <-ctx.Done():
		return cliproxyexecutor.Response{}, ctx.Err()
	case <-probe.complete:
		if probe.upstreamFailure {
			return cliproxyexecutor.Response{}, errors.New("synthetic upstream failure")
		}
		return cliproxyexecutor.Response{}, nil
	}
}

func newStage1BProbe() *stage1BProbe {
	return &stage1BProbe{entered: make(chan struct{}), sent: make(chan struct{}), finished: make(chan struct{})}
}

func TestPoolStage1BLeaseDispatchAndTermination(t *testing.T) {
	for _, scenario := range []string{"cached-select", "before-dispatch", "after-dispatch", "client-cancel", "upstream-error", "completion", "panic"} {
		t.Run(scenario, func(t *testing.T) {
			m, _, auth, _, _ := poolGuardFixture(t, "service")
			m.SetRetryConfig(3, 0, 3)
			probe := newStage1BProbe()
			m.RegisterExecutor(probe)
			if scenario == "cached-select" {
				ctx, _ := m.poolExecutionContext(context.Background())
				poolRevoke(t, m)
				executor, _ := m.Executor("codex")
				_, err := executor.Execute(ctx, auth, cliproxyexecutor.Request{Model: "synthetic-native"}, cliproxyexecutor.Options{})
				if err == nil || probe.calls.Load() != 0 {
					t.Fatal("cached selection dispatched")
				}
				return
			}
			permit := make(chan struct{})
			completion := make(chan struct{})
			if scenario == "before-dispatch" {
				probe.permit = permit
			}
			probe.complete = completion
			probe.panicBefore = scenario == "panic"
			probe.upstreamFailure = scenario == "upstream-error"
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			result := make(chan error, 1)
			go func() {
				defer func() {
					if recover() != nil {
						result <- errors.New("recovered synthetic panic")
					}
				}()
				_, err := m.Execute(ctx, []string{"codex"}, cliproxyexecutor.Request{Model: "synthetic-native"}, cliproxyexecutor.Options{})
				result <- err
			}()
			waitPoolSignal(t, probe.entered)
			if scenario == "before-dispatch" {
				poolRevoke(t, m)
				close(permit)
			} else if scenario != "panic" {
				waitPoolSignal(t, probe.sent)
				switch scenario {
				case "after-dispatch":
					poolRevoke(t, m)
				case "client-cancel":
					var g sync.WaitGroup
					g.Go(cancel)
					g.Go(func() { poolRevoke(t, m) })
					g.Wait()
				default:
					var g sync.WaitGroup
					g.Go(func() { close(completion) })
					g.Go(func() { poolRevoke(t, m) })
					g.Wait()
				}
			}
			select {
			case err := <-result:
				if scenario == "after-dispatch" || scenario == "before-dispatch" {
					if !errors.Is(err, ErrAccountRevoked) {
						t.Fatal("lost revoke reason", err)
					}
				}
			case <-time.After(3 * time.Second):
				t.Fatal("request did not terminate")
			}
			waitPoolSignal(t, probe.finished)
			if len(m.PoolInFlightSnapshot()) != 0 {
				t.Fatal("in-flight leaked")
			}
			if scenario == "before-dispatch" && probe.calls.Load() != 0 {
				t.Fatal("upstream received pre-dispatch revoke")
			}
			if probe.calls.Load() > 1 {
				t.Fatal("revoked attempt replayed")
			}
		})
	}
}

func TestPoolStage1BStreamRevokeTerminatesAndDoesNotReplay(t *testing.T) {
	m, probe, _, _, _ := poolGuardFixture(t, "service")
	m.SetRetryConfig(3, 0, 3)
	probe.stream = make(chan cliproxyexecutor.StreamChunk, 1)
	probe.stream <- cliproxyexecutor.StreamChunk{Payload: []byte("data: synthetic\n\n")}
	result, err := m.ExecuteStream(context.Background(), []string{"codex"}, cliproxyexecutor.Request{Model: "synthetic-native"}, cliproxyexecutor.Options{Stream: true})
	if err != nil {
		t.Fatal(err)
	}
	<-result.Chunks
	poolRevoke(t, m)
	done := make(chan struct{})
	var terminal error
	go func() {
		defer close(done)
		for chunk := range result.Chunks {
			if chunk.Err != nil {
				terminal = chunk.Err
			}
		}
	}()
	waitPoolSignal(t, done)
	if !errors.Is(terminal, ErrAccountRevoked) || probe.calls.Load() != 1 || len(m.PoolInFlightSnapshot()) != 0 {
		t.Fatal("stream revoke failed", terminal)
	}
}

func TestPoolStage1BRestartAndCorruption(t *testing.T) {
	for _, scenario := range []string{"trusted", "revoked", "trust-corrupt", "generation-mismatch", "identity-mismatch", "authorization-replay", "missing-journal"} {
		t.Run(scenario, func(t *testing.T) {
			m, probe, auth, file, record := poolGuardFixture(t, "service")
			switch scenario {
			case "revoked":
				poolRevoke(t, m)
			case "trust-corrupt", "generation-mismatch":
				data, err := os.ReadFile(m.poolGuard.checkpoint)
				if err != nil {
					t.Fatal(err)
				}
				lines := bytes.Split(bytes.TrimSuffix(data, []byte{'\n'}), []byte{'\n'})
				var last poolCheckpoint
				if json.Unmarshal(lines[len(lines)-1], &last) != nil {
					t.Fatal("fixture")
				}
				if scenario == "trust-corrupt" {
					last.Trust[0].State = PoolTrustPending
				} else {
					last.Trust[0].Generation++
				}
				lines[len(lines)-1], _ = json.Marshal(last)
				if os.WriteFile(m.poolGuard.checkpoint, append(bytes.Join(lines, []byte{'\n'}), '\n'), 0600) != nil {
					t.Fatal("write fixture")
				}
			case "identity-mismatch":
				auth.Metadata["account_id"] = "synthetic-account-id-other"
			case "authorization-replay":
				record.Revision--
				writePoolGrant(t, file, record)
			case "missing-journal":
				m.poolGuard.checkpoint = filepath.Join(t.TempDir(), "missing")
				t.Setenv("CLEARAPI_POOL_CHECKPOINT_FILE", m.poolGuard.checkpoint)
			}
			restarted := NewManager(nil, nil, nil)
			restarted.SetConfig(m.runtimeConfigSnapshot())
			restarted.RegisterExecutor(probe)
			_, err := restarted.Register(context.Background(), auth)
			if err != nil {
				t.Fatal(err)
			}
			err = poolRequest(restarted)
			if scenario == "trusted" {
				if err != nil || probe.calls.Load() != 1 {
					t.Fatal("trusted did not recover", err)
				}
			} else if err == nil || probe.calls.Load() != 0 {
				t.Fatal("unsafe restart executed")
			}
		})
	}
}

func TestPoolStage1BResourceCloseExactlyOnce(t *testing.T) {
	m, _, auth, _, _ := poolGuardFixture(t, "service")
	wrapped, _ := m.Executor("codex")
	ctx, _ := m.poolExecutionContext(context.Background())
	lease, err := wrapped.(*poolExecutor).begin(ctx, auth, cliproxyexecutor.Request{Model: "synthetic-native"}, cliproxyexecutor.Options{}, false, true)
	if err != nil {
		t.Fatal(err)
	}
	var closes atomic.Int32
	closed := make(chan struct{})
	if err := lease.Bind(func() error {
		if closes.Add(1) != 1 {
			t.Error("double close")
		}
		close(closed)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	var group sync.WaitGroup
	group.Go(func() { poolRevoke(t, m) })
	group.Go(func() { lease.End("completed") })
	group.Go(func() { lease.End("duplicate") })
	group.Wait()
	waitPoolSignal(t, closed)
	if len(m.PoolInFlightSnapshot()) != 0 || closes.Load() != 1 {
		t.Fatal("resource leaked")
	}
}

func TestPoolStage1BLeaseAcquireRevokeRace(t *testing.T) {
	m, probe, auth, _, _ := poolGuardFixture(t, "service")
	wrapped, _ := m.Executor("codex")
	ctx, _ := m.poolExecutionContext(context.Background())
	var lease *poolLease
	var beginErr error
	start := make(chan struct{})
	var group sync.WaitGroup
	group.Go(func() {
		<-start
		lease, beginErr = wrapped.(*poolExecutor).begin(ctx, auth, cliproxyexecutor.Request{Model: "synthetic-native"}, cliproxyexecutor.Options{}, false, true)
	})
	group.Go(func() { <-start; poolRevoke(t, m) })
	close(start)
	group.Wait()
	if beginErr == nil {
		if lease.AuthorizeDispatch() == nil {
			t.Fatal("racing old lease authorized")
		}
		lease.End("rejected")
	}
	if probe.calls.Load() != 0 || len(m.PoolInFlightSnapshot()) != 0 {
		t.Fatal("racing acquire leaked or dispatched")
	}
}
