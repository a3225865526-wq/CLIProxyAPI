package cliproxy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/api/handlers/management"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
	filestore "github.com/router-for-me/CLIProxyAPI/v8/sdk/auth"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	ex "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/config"
)

type pg02CommitStore struct {
	*filestore.FileTokenStore
	fail       atomic.Bool
	afterWrite bool
	entered    chan struct{}
	release    chan struct{}
}

func (s *pg02CommitStore) Save(ctx context.Context, a *coreauth.Auth) (string, error) {
	if s.fail.Load() {
		if s.entered != nil {
			close(s.entered)
			<-s.release
		}
		if s.afterWrite {
			if _, err := s.FileTokenStore.Save(ctx, a); err != nil {
				return "", err
			}
		}
		return "", errors.New("synthetic commit failure")
	}
	return s.FileTokenStore.Save(ctx, a)
}

type pg02CommitFixture struct {
	m     *coreauth.Manager
	s     *Service
	store *pg02CommitStore
	h     *management.Handler
	id    string
	path  string
}

func newPG02CommitFixture(t *testing.T) *pg02CommitFixture {
	t.Helper()
	ctx := context.Background()
	root := t.TempDir()
	dir := filepath.Join(root, "auths")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	grants, checkpoint := filepath.Join(root, "grants.json"), filepath.Join(root, "checkpoint.jsonl")
	t.Setenv("MANAGEMENT_PASSWORD", "")
	t.Setenv("CLEARAPI_POOL_ROLE", "service")
	t.Setenv("CLEARAPI_POOL_ADMISSION_FILE", grants)
	t.Setenv("CLEARAPI_POOL_EXECUTOR_ID", "synthetic-service")
	t.Setenv("CLEARAPI_POOL_CHECKPOINT_FILE", checkpoint)
	if err := coreauth.ProvisionPoolCheckpoint(checkpoint, "synthetic-service"); err != nil {
		t.Fatal(err)
	}
	a := &coreauth.Auth{ID: "synthetic-commit.json", FileName: "synthetic-commit.json", Provider: "codex", Status: coreauth.StatusActive,
		Attributes: map[string]string{coreauth.AttributeAuthKind: coreauth.AuthKindOAuth, "plan_type": "pro"},
		Metadata:   map[string]any{"type": "codex", "access_token": "synthetic-unused", "account_id": "synthetic-commit", "email": "commit@test.invalid"}}
	record := coreauth.PoolGrantFile{GuardVersion: coreauth.PoolGuardVersion, Revision: 1, ExecutorID: "synthetic-service", Grants: []coreauth.PoolGrant{{
		AuthID: a.ID, Provider: a.Provider, CredentialDigest: coreauth.PoolCredentialDigest(a), Models: []string{"gpt-5.6-luna"},
		Capabilities: []string{"text_chat", "stream_text", "exact_usage"}, Enabled: true, MaxConcurrency: 1,
		ExpiresAt: time.Now().Add(25 * time.Minute).Unix(), SourceEvidence: []string{"synthetic-source"}, TestEvidence: []string{"synthetic-test"}}}}
	body, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(grants, body, 0600); err != nil {
		t.Fatal(err)
	}
	base := filestore.NewFileTokenStore()
	base.SetBaseDir(dir)
	store := &pg02CommitStore{FileTokenStore: base}
	cfg := &config.Config{AuthDir: dir}
	if _, err = store.Save(coreauth.WithAuthCreationIntent(ctx), a); err != nil {
		t.Fatal(err)
	}
	m := coreauth.NewManager(store, nil, nil)
	m.SetConfig(cfg)
	m.RegisterExecutor(&syncTestExecutor{})
	if a, err = m.Register(ctx, a); err != nil {
		t.Fatal(err)
	}
	s := &Service{cfg: cfg, coreManager: m}
	m.SetPoolRegistrySync(s.syncPoolRegistry)
	t.Cleanup(func() { registry.GetGlobalRegistry().UnregisterClient(a.ID) })
	identity := func() (uint64, coreauth.PoolIdentityExpectation) {
		rev, states, errSnapshot := m.PoolTrustSnapshot()
		if errSnapshot != nil {
			t.Fatal(errSnapshot)
		}
		id := coreauth.PoolIdentityExpectation{AuthID: a.ID, Provider: a.Provider, CredentialDigest: coreauth.PoolCredentialDigest(a)}
		for _, state := range states {
			if state.AuthID == a.ID {
				id.Generation = state.Generation
			}
		}
		return rev, id
	}
	rev, id := identity()
	if err = m.PromotePoolIdentities(ctx, coreauth.PoolPromotion{ExpectedRevision: rev, Identities: []coreauth.PoolIdentityExpectation{id}}); err != nil {
		t.Fatal(err)
	}
	rev, id = identity()
	if err = m.GrantPoolModelCapability(ctx, coreauth.PoolModelGrant{ExpectedRevision: rev, Identity: id, Model: "gpt-5.6-luna"}); err != nil {
		t.Fatal(err)
	}
	h := management.NewHandlerWithoutConfigFilePath(cfg, m)
	h.SetPostAuthPersistHook(func(ctx context.Context, _ *coreauth.Auth) error { return s.syncPoolRegistry(ctx) })
	return &pg02CommitFixture{m: m, s: s, store: store, h: h, id: a.ID, path: filepath.Join(dir, a.FileName)}
}

func (f *pg02CommitFixture) patch(disabled bool) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(rec)
	ctx.Request = httptest.NewRequest(http.MethodPatch, "/v0/management/auth-files/status", strings.NewReader(fmt.Sprintf(`{"name":%q,"disabled":%t}`, f.id, disabled)))
	ctx.Request.Header.Set("Content-Type", "application/json")
	f.h.PatchAuthFileStatus(ctx)
	return rec
}

func (f *pg02CommitFixture) check(t *testing.T, m *coreauth.Manager, disabled bool) {
	t.Helper()
	a, ok := m.GetByID(f.id)
	if !ok || a.Disabled != disabled {
		t.Fatalf("Manager disabled: %+v, want %t", a, disabled)
	}
	p, err := m.PoolRequestPreflight(context.Background(), "gpt-5.6-luna", ex.Options{OriginalRequest: []byte(`{"model":"gpt-5.6-luna"}`)})
	want := 1
	if disabled {
		want = 0
	}
	if p.EligibleCount != want || (!disabled && err != nil) {
		t.Fatalf("admission: %+v %v, want %d", p, err, want)
	}
	if count := len(registry.GetGlobalRegistry().GetModelsForClient(f.id)); count != want {
		t.Fatalf("Registry models=%d, want %d", count, want)
	}
}

func (f *pg02CommitFixture) diskDisabled(t *testing.T) bool {
	t.Helper()
	data, err := os.ReadFile(f.path)
	if err != nil {
		t.Fatal(err)
	}
	var meta map[string]any
	if err = json.Unmarshal(data, &meta); err != nil {
		t.Fatal(err)
	}
	disabled, ok := meta["disabled"].(bool)
	if !ok {
		t.Fatal("missing committed disabled field")
	}
	return disabled
}

func (f *pg02CommitFixture) restart(t *testing.T, disabled bool) {
	t.Helper()
	m := coreauth.NewManager(f.store.FileTokenStore, nil, nil)
	m.SetConfig(f.s.cfg)
	m.RegisterExecutor(&syncTestExecutor{})
	s := &Service{cfg: f.s.cfg, coreManager: m}
	m.SetPoolRegistrySync(s.syncPoolRegistry)
	if err := m.Load(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := s.syncPoolRegistry(context.Background()); err != nil {
		t.Fatal(err)
	}
	f.check(t, m, disabled)
	if err := f.s.syncPoolRegistry(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestPG02ManagementCommitMatrix(t *testing.T) {
	for _, afterWrite := range []bool{false, true} {
		t.Run(fmt.Sprintf("error_after_write_%t", afterWrite), func(t *testing.T) {
			f := newPG02CommitFixture(t)
			f.check(t, f.m, false)
			f.store.afterWrite = afterWrite
			f.store.fail.Store(true)
			if rec := f.patch(true); rec.Code != http.StatusInternalServerError {
				t.Fatalf("failed disable: %d %s", rec.Code, rec.Body.String())
			}
			f.check(t, f.m, true)
			if got := f.diskDisabled(t); got != afterWrite {
				t.Fatalf("failed disable disk=%t, want %t", got, afterWrite)
			}
			f.restart(t, afterWrite)
			f.store.fail.Store(false)
			if rec := f.patch(true); rec.Code != http.StatusOK {
				t.Fatalf("disable: %d %s", rec.Code, rec.Body.String())
			}
			f.check(t, f.m, true)
			f.restart(t, true)
			f.store.fail.Store(true)
			before, _ := f.m.GetByID(f.id)
			if rec := f.patch(false); rec.Code != http.StatusInternalServerError {
				t.Fatalf("failed recovery: %d %s", rec.Code, rec.Body.String())
			}
			f.check(t, f.m, true)
			after, _ := f.m.GetByID(f.id)
			if after.Generation != before.Generation {
				t.Fatal("failed recovery published a new generation")
			}
			// Error-after-write is an UNKNOWN result. The account may already
			// contain enabled bytes, so restart must quarantine it until a fresh
			// durable disable is established.
			if afterWrite {
				if f.diskDisabled(t) {
					t.Fatal("ambiguous recovery unexpectedly left the account disabled on disk")
				}
				f.restart(t, true)
				if rec := f.patch(true); rec.Code != http.StatusOK {
					t.Fatalf("re-isolation after UNKNOWN recovery: %d %s", rec.Code, rec.Body.String())
				}
				f.check(t, f.m, true)
			}
			f.store.fail.Store(false)
			if rec := f.patch(false); rec.Code != http.StatusOK {
				t.Fatalf("recovery: %d %s", rec.Code, rec.Body.String())
			}
			f.check(t, f.m, false)
			f.restart(t, false)
		})
	}
}

func TestPG02ManagementWatcherFailureInterleave(t *testing.T) {
	f := newPG02CommitFixture(t)
	stale, _ := f.m.GetByID(f.id)
	staleGeneration := stale.Generation
	f.store.entered, f.store.release = make(chan struct{}), make(chan struct{})
	f.store.fail.Store(true)
	apiDone := make(chan *httptest.ResponseRecorder, 1)
	go func() { apiDone <- f.patch(true) }()
	<-f.store.entered
	watcherDone := make(chan error, 1)
	go func() {
		_, err := f.m.Update(coreauth.WithSkipPersist(context.Background()), stale)
		watcherDone <- err
	}()
	close(f.store.release)
	if rec := <-apiDone; rec.Code != http.StatusInternalServerError {
		t.Fatalf("disable unexpectedly succeeded: %d", rec.Code)
	}
	if err := <-watcherDone; err != nil {
		t.Fatal(err)
	}
	f.check(t, f.m, true)
	current, _ := f.m.GetByID(f.id)
	if current.Generation <= staleGeneration {
		t.Fatal("generation did not advance")
	}
}

func TestPG02ManagementDisableThenPromotionDoesNotRecover(t *testing.T) {
	f := newPG02CommitFixture(t)
	if rec := f.patch(true); rec.Code != http.StatusOK {
		t.Fatalf("formal disable: %d %s", rec.Code, rec.Body.String())
	}
	f.restart(t, true)
	rev, states, err := f.m.PoolTrustSnapshot()
	if err != nil {
		t.Fatal(err)
	}
	a, _ := f.m.GetByID(f.id)
	id := coreauth.PoolIdentityExpectation{AuthID: f.id, Provider: a.Provider, CredentialDigest: coreauth.PoolCredentialDigest(a)}
	for _, state := range states {
		if state.AuthID == f.id {
			id.Generation = state.Generation
		}
	}
	if err = f.m.PromotePoolIdentities(context.Background(), coreauth.PoolPromotion{ExpectedRevision: rev, Identities: []coreauth.PoolIdentityExpectation{id}}); err != nil {
		t.Fatal(err)
	}
	a, _ = f.m.GetByID(f.id)
	if !a.Disabled || !f.diskDisabled(t) {
		t.Error("UNRESOLVED: promotion removed a committed management disable without a recovery request")
	}
	// Regrant only model capability, not management recovery. Demonstrate that
	// promotion's implicit enable can regain actual dispatch qualification.
	rev, states, err = f.m.PoolTrustSnapshot()
	if err != nil {
		t.Fatal(err)
	}
	for _, state := range states {
		if state.AuthID == f.id {
			id.Generation = state.Generation
		}
	}
	if err = f.m.GrantPoolModelCapability(context.Background(), coreauth.PoolModelGrant{ExpectedRevision: rev, Identity: id, Model: "gpt-5.6-luna"}); err != nil {
		t.Fatal(err)
	}
	p, err := f.m.PoolRequestPreflight(context.Background(), "gpt-5.6-luna", ex.Options{OriginalRequest: []byte(`{"model":"gpt-5.6-luna"}`)})
	if err == nil && p.EligibleCount != 0 {
		t.Errorf("UNRESOLVED: promotion plus model-only regrant reopened admission: %+v", p)
	}
}
