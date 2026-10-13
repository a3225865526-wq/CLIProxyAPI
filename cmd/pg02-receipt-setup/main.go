// This fixture provisions only synthetic identities. It never writes receipts.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	filestore "github.com/router-for-me/CLIProxyAPI/v8/sdk/auth"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/config"
)

func run() error {
	root := "/private"
	dir := filepath.Join(root, "auths")
	for _, path := range []string{dir, filepath.Join(root, "transport")} {
		if err := os.MkdirAll(path, 0700); err != nil {
			return err
		}
		if err := os.Chmod(path, 0700); err != nil {
			return err
		}
	}
	grants, checkpoint := filepath.Join(root, "grants.json"), filepath.Join(root, "floor.jsonl")
	for key, value := range map[string]string{
		"CLEARAPI_POOL_ROLE":            "service",
		"CLEARAPI_POOL_EXECUTOR_ID":     "receipt-mock-executor",
		"CLEARAPI_POOL_ADMISSION_FILE":  grants,
		"CLEARAPI_POOL_CHECKPOINT_FILE": checkpoint,
	} {
		if err := os.Setenv(key, value); err != nil {
			return err
		}
	}
	if err := coreauth.ProvisionPoolCheckpoint(checkpoint, "receipt-mock-executor"); err != nil {
		return err
	}
	ids := []string{"codex-real-test.json", "codex-mock-b.json"}
	record := coreauth.PoolGrantFile{GuardVersion: coreauth.PoolGuardVersion, ExecutorID: "receipt-mock-executor", Revision: 1}
	for i, id := range ids {
		metadata := map[string]any{
			"type":         "codex",
			"access_token": fmt.Sprintf("synthetic-offline-%d", i),
			"account_id":   fmt.Sprintf("synthetic-offline-account-%d", i),
			"email":        fmt.Sprintf("mock-%d@invalid.example", i),
			"base_url":     "http://127.0.0.1:19100",
			"plan_type":    "pro",
			"priority":     100 - i,
			"disabled":     false,
		}
		body, err := json.Marshal(metadata)
		if err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(dir, id), body, 0600); err != nil {
			return err
		}
		a := &coreauth.Auth{ID: id, Provider: "codex", Metadata: metadata, Attributes: map[string]string{coreauth.AttributeAuthKind: coreauth.AuthKindOAuth}}
		record.Grants = append(record.Grants, coreauth.PoolGrant{
			AuthID: id, Provider: "codex", CredentialDigest: coreauth.PoolCredentialDigest(a), Models: []string{"gpt-5.6-luna"},
			Capabilities: []string{"text_chat", "exact_usage"}, Enabled: true, MaxConcurrency: 4,
			ExpiresAt: time.Now().Add(25 * time.Minute).Unix(), SourceEvidence: []string{"synthetic-local-only"}, TestEvidence: []string{"receipt-service-mock"},
		})
	}
	body, err := json.Marshal(record)
	if err != nil {
		return err
	}
	if err := os.WriteFile(grants, body, 0600); err != nil {
		return err
	}
	store := filestore.NewFileTokenStore()
	store.SetBaseDir(dir)
	m := coreauth.NewManager(store, nil, nil)
	m.SetConfig(&config.Config{AuthDir: dir})
	ctx := context.Background()
	if err := m.Load(ctx); err != nil {
		return err
	}
	pending, err := m.PoolPendingIdentities()
	if err != nil {
		return err
	}
	if len(pending) != 2 {
		return fmt.Errorf("synthetic identities: %d", len(pending))
	}
	if err := m.PromotePoolIdentities(ctx, coreauth.PoolPromotion{ExpectedRevision: 1, Identities: pending}); err != nil {
		return err
	}
	for _, id := range ids {
		revision, trust, err := m.PoolTrustSnapshot()
		if err != nil {
			return err
		}
		for _, identity := range trust {
			if identity.AuthID != id {
				continue
			}
			if err := m.GrantPoolModelCapability(ctx, coreauth.PoolModelGrant{
				ExpectedRevision: revision,
				Identity:         coreauth.PoolIdentityExpectation{AuthID: id, Provider: identity.Provider, CredentialDigest: identity.CredentialDigest, Generation: identity.Generation, IdentityVersion: identity.IdentityVersion},
				Model:            "gpt-5.6-luna",
			}); err != nil {
				return err
			}
		}
	}
	revision, trust, err := m.PoolTrustSnapshot()
	if err != nil {
		return err
	}
	body, err = json.Marshal(map[string]any{"revision": revision, "identities": trust})
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(root, "fixture-identities.json"), body, 0600)
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
