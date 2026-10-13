package cliproxy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
	filestore "github.com/router-for-me/CLIProxyAPI/v8/sdk/auth"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	ex "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/config"
)

func pg02IsolationCommand(t *testing.T, f *pg02CommitFixture) coreauth.PoolPromotion {
	t.Helper()
	rev, states, errSnapshot := f.m.PoolTrustSnapshot()
	if errSnapshot != nil {
		t.Fatal(errSnapshot)
	}
	a, _ := f.m.GetByID(f.id)
	id := coreauth.PoolIdentityExpectation{AuthID: a.ID, Provider: a.Provider, CredentialDigest: coreauth.PoolCredentialDigest(a)}
	for _, state := range states {
		if state.AuthID == a.ID {
			id.Generation = state.Generation
		}
	}
	return coreauth.PoolPromotion{ExpectedRevision: rev, Identities: []coreauth.PoolIdentityExpectation{id}}
}

func pg02IsolationPromote(f *pg02CommitFixture, command coreauth.PoolPromotion) *httptest.ResponseRecorder {
	raw, _ := json.Marshal(command)
	response := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(response)
	c.Request = httptest.NewRequest(http.MethodPost, "/v0/management/pool/trust/promote", bytes.NewReader(raw))
	f.h.PromotePoolTrust(c)
	return response
}

func pg02IsolationDiskFlag(t *testing.T, f *pg02CommitFixture) {
	t.Helper()
	raw, errRead := os.ReadFile(f.path)
	if errRead != nil {
		t.Fatal(errRead)
	}
	var metadata map[string]any
	if errDecode := json.Unmarshal(raw, &metadata); errDecode != nil {
		t.Fatal(errDecode)
	}
	if metadata[coreauth.ManagementDisabledKey] != true || metadata["disabled"] != true {
		t.Fatal("formal management isolation was not preserved on disk")
	}
}

func TestPG02ManagementIsolationP0PromotionWatcherRestart(t *testing.T) {
	f := newPG02CommitFixture(t)
	f.check(t, f.m, false)
	stale, _ := f.m.GetByID(f.id)
	if response := f.patch(true); response.Code != http.StatusOK {
		t.Fatalf("disable: %d %s", response.Code, response.Body.String())
	}
	for i := 0; i < 2; i++ {
		if response := pg02IsolationPromote(f, pg02IsolationCommand(t, f)); response.Code != http.StatusOK {
			t.Fatalf("promotion: %d %s", response.Code, response.Body.String())
		}
		command := pg02IsolationCommand(t, f)
		if errGrant := f.m.GrantPoolModelCapability(context.Background(), coreauth.PoolModelGrant{ExpectedRevision: command.ExpectedRevision, Identity: command.Identities[0], Model: "gpt-5.6-luna"}); errGrant != nil {
			t.Fatal(errGrant)
		}
		f.check(t, f.m, true)
		pg02IsolationDiskFlag(t, f)
	}
	stale.Metadata[coreauth.ManagementDisabledKey] = false
	stale.Disabled, stale.Status = false, coreauth.StatusActive
	oldPublication := stale.Clone()
	if _, errUpdate := f.m.Update(coreauth.WithSkipPersist(context.Background()), stale); errUpdate != nil {
		t.Fatal(errUpdate)
	}
	if f.m.PublishPoolModels(oldPublication, oldPublication.Provider, []*registry.ModelInfo{{ID: "gpt-5.6-luna"}}) {
		t.Fatal("old generation published models")
	}
	f.check(t, f.m, true)
	f.restart(t, true)
	child := exec.Command(os.Args[0], "-test.run=^TestPG02ManagementIsolationP0Child$", "-test.count=1", "-test.v")
	child.Env = append(os.Environ(), "P0_ISOLATION_CHILD_DIR="+filepath.Dir(f.path))
	if output, errChild := child.CombinedOutput(); errChild != nil {
		t.Fatalf("fresh-process eligibility check: %v %s", errChild, output)
	}
}

type pg02IsolationProbe struct {
	syncTestExecutor
	calls atomic.Int64
}

func (p *pg02IsolationProbe) Execute(context.Context, *coreauth.Auth, ex.Request, ex.Options) (ex.Response, error) {
	p.calls.Add(1)
	return ex.Response{}, nil
}

func TestPG02ManagementIsolationP0Child(t *testing.T) {
	dir := os.Getenv("P0_ISOLATION_CHILD_DIR")
	if dir == "" {
		t.Skip("isolated subprocess helper")
	}
	store := filestore.NewFileTokenStore()
	store.SetBaseDir(dir)
	cfg := &config.Config{AuthDir: dir}
	m := coreauth.NewManager(store, nil, nil)
	m.SetConfig(cfg)
	probe := &pg02IsolationProbe{}
	m.RegisterExecutor(probe)
	s := &Service{cfg: cfg, coreManager: m}
	m.SetPoolRegistrySync(s.syncPoolRegistry)
	if errLoad := m.Load(context.Background()); errLoad != nil {
		t.Fatal(errLoad)
	}
	if errSync := s.syncPoolRegistry(context.Background()); errSync != nil {
		t.Fatal(errSync)
	}
	f := &pg02CommitFixture{id: "synthetic-commit.json"}
	f.check(t, m, true)
	preflight, errDispatch := m.PoolRequestPreflight(context.Background(), "gpt-5.6-luna", ex.Options{OriginalRequest: []byte(`{"model":"gpt-5.6-luna"}`)})
	if errDispatch == nil && preflight.EligibleCount != 0 || probe.calls.Load() != 0 {
		t.Fatal("new process dispatched isolated credential")
	}
}

func TestPG02ManagementIsolationP0AmbiguousRecoveryRemainsIsolated(t *testing.T) {
	f := newPG02CommitFixture(t)
	if response := f.patch(true); response.Code != http.StatusOK {
		t.Fatalf("disable: %d %s", response.Code, response.Body.String())
	}
	before, _ := os.ReadFile(f.path)
	current, _ := f.m.GetByID(f.id)
	f.store.afterWrite = true
	f.store.fail.Store(true)
	for i := 0; i < 2; i++ {
		if response := f.patch(false); response.Code != http.StatusInternalServerError || !strings.Contains(response.Body.String(), "UNKNOWN") {
			t.Fatalf("ambiguous recovery: %d %s", response.Code, response.Body.String())
		}
	}
	after, _ := os.ReadFile(f.path)
	installed, _ := f.m.GetByID(f.id)
	if bytes.Equal(before, after) || installed.Generation != current.Generation {
		t.Fatal("ambiguous recovery did not preserve runtime isolation and generation")
	}
	f.check(t, f.m, true)
	f.restart(t, true)
}

func TestPG02ManagementIsolationP0ConcurrentDisablePromotionRecovery(t *testing.T) {
	f := newPG02CommitFixture(t)
	if response := f.patch(true); response.Code != http.StatusOK {
		t.Fatalf("durable isolation baseline: %d %s", response.Code, response.Body.String())
	}
	// Recovery is unqualified only when a required durable write cannot commit.
	// Starting enabled with a healthy store permits disable -> WAL recovery ->
	// promotion, so unconditional rejection is not a valid concurrency contract.
	f.store.fail.Store(true)
	command := pg02IsolationCommand(t, f)
	start := make(chan struct{})
	disabled := make(chan *httptest.ResponseRecorder, 1)
	promoted := make(chan *httptest.ResponseRecorder, 1)
	recovered := make(chan *httptest.ResponseRecorder, 1)
	go func() { <-start; disabled <- f.patch(true) }()
	go func() { <-start; promoted <- pg02IsolationPromote(f, command) }()
	go func() { <-start; recovered <- f.patch(false) }()
	close(start)
	disableResponse, promotionResponse, recoveryResponse := <-disabled, <-promoted, <-recovered
	if promotionResponse.Code != http.StatusOK {
		t.Fatalf("promotion: %d %s", promotionResponse.Code, promotionResponse.Body.String())
	}
	if recoveryResponse.Code != http.StatusInternalServerError || !strings.Contains(recoveryResponse.Body.String(), "NOT_COMMITTED") {
		t.Fatalf("unexpected recovery outcome: recovery=%d %s disable=%d %s promotion=%d %s", recoveryResponse.Code, recoveryResponse.Body.String(), disableResponse.Code, disableResponse.Body.String(), promotionResponse.Code, promotionResponse.Body.String())
	}
	if disableResponse.Code != http.StatusOK {
		// The explicit status CAS may lose to promotion; it must never report
		// durable success for a stale snapshot. A fresh disable remains legal.
		if !strings.Contains(disableResponse.Body.String(), "stale") {
			t.Fatalf("unexpected disable error: %s", disableResponse.Body.String())
		}
		if response := f.patch(true); response.Code != http.StatusOK {
			t.Fatalf("fresh disable: %d %s", response.Code, response.Body.String())
		}
	}
	f.check(t, f.m, true)
	pg02IsolationDiskFlag(t, f)
	f.restart(t, true)
}

func TestPG02ManagementIsolationP0CommittedDisableHookError(t *testing.T) {
	f := newPG02CommitFixture(t)
	f.h.SetPostAuthPersistHook(func(context.Context, *coreauth.Auth) error { return errors.New("synthetic publication failure") })
	response := f.patch(true)
	if response.Code != http.StatusInternalServerError || !strings.Contains(response.Body.String(), `"commit_status":"COMMITTED"`) {
		t.Fatalf("commit outcome: %d %s", response.Code, response.Body.String())
	}
	pg02IsolationDiskFlag(t, f)
	f.restart(t, true)
}
