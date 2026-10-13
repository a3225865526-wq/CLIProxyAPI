package executor

import (
	"context"
	"fmt"
	"sync"
	"testing"

	claudeauth "github.com/router-for-me/CLIProxyAPI/v8/internal/auth/claude"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
)

// A single Auth is shared by every in-flight request that selects the credential,
// so any request path reaching into Auth.Metadata directly races the others. An
// earlier fix locked only the device pool helpers and left the account-profile
// path unguarded, which these tests would have caught: they drive the exported
// entry points rather than the helper that was known to be broken.

func newSharedClaudeOAuthAuth(id string) *cliproxyauth.Auth {
	return &cliproxyauth.Auth{
		ID:         id,
		Attributes: map[string]string{"api_key": "sk-ant-oat-race-probe"},
		Metadata:   map[string]any{},
	}
}

func TestClaudeExecutorPrepareRequestAuthIsRaceFreeOnSharedCredential(t *testing.T) {
	executor := NewClaudeExecutor(&config.Config{})
	executor.oauthProfileFetcher = func(context.Context, *cliproxyauth.Auth, string) (*claudeauth.OAuthProfile, error) {
		profile := &claudeauth.OAuthProfile{}
		profile.Account.UUID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
		profile.Account.Email = "user@example.com"
		profile.Organization.UUID = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
		profile.Organization.Name = "Example Org"
		return profile, nil
	}

	auth := newSharedClaudeOAuthAuth("claude-race-prepare")
	ctx := context.Background()

	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// ShouldPrepareRequestAuth reads the same map the writers below mutate.
			if executor.ShouldPrepareRequestAuth(auth) {
				if _, err := executor.PrepareRequestAuth(ctx, auth); err != nil {
					t.Errorf("PrepareRequestAuth() error = %v", err)
				}
				return
			}
			_ = executor.ShouldPrepareRequestAuth(auth)
		}()
	}
	wg.Wait()

	if got := claudeauth.ReadMetadataString(&auth.Metadata, "account_uuid"); got != "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa" {
		t.Fatalf("account_uuid = %q, want the fetched profile account", got)
	}
	if !claudeauth.HasCanonicalDeviceIDPool(claudeauth.ReadDeviceIDPool(&auth.Metadata)) {
		t.Fatal("device ID pool was not established under concurrency")
	}
}

// TestClaudeExecutorSharedCredentialMetadataMixedAccess drives the request-path
// readers against the profile writer at the same time, which is the shape that
// produced the reported data races.
func TestClaudeExecutorSharedCredentialMetadataReadersUseOneLock(t *testing.T) {
	auth := &cliproxyauth.Auth{ID: "claude-race-all-readers", Metadata: map[string]any{
		"access_token":          "sk-ant-oat-race-probe",
		"cloak_mode":            "always",
		"cloak_sensitive_words": "secret",
	}}

	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			if i%3 == 0 {
				claudeauth.StoreMetadataValue(&auth.Metadata, "access_token", "sk-ant-oat-race-probe")
				claudeauth.StoreMetadataValue(&auth.Metadata, "cloak_mode", "always")
				return
			}
			if i%3 == 1 {
				_, _ = claudeCreds(auth)
				return
			}
			_, _, _, _ = getCloakConfigFromAuth(auth)
		}(i)
	}
	close(start)
	wg.Wait()
}

func TestClaudeExecutorSharedCredentialMetadataMixedAccess(t *testing.T) {
	executor := NewClaudeExecutor(&config.Config{})
	executor.oauthProfileFetcher = func(context.Context, *cliproxyauth.Auth, string) (*claudeauth.OAuthProfile, error) {
		profile := &claudeauth.OAuthProfile{}
		profile.Account.UUID = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
		return profile, nil
	}

	auth := newSharedClaudeOAuthAuth("claude-race-mixed")
	ctx := context.Background()

	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			switch i % 4 {
			case 0:
				if _, err := executor.PrepareRequestAuth(ctx, auth); err != nil {
					t.Errorf("PrepareRequestAuth() error = %v", err)
				}
			case 1:
				_ = executor.ShouldPrepareRequestAuth(auth)
			case 2:
				_ = claudeauth.ReadMetadataString(&auth.Metadata, "account_uuid")
			default:
				_ = claudeauth.ReadDeviceIDPool(&auth.Metadata)
			}
		}(i)
	}
	wg.Wait()
}

// Setup-token checks must share the lock used by profile and device-pool writes,
// including when the map is initialized by a concurrent request.
func TestClaudeExecutorSetupTokenMetadataConcurrentAccess(t *testing.T) {
	for _, initialized := range []bool{false, true} {
		t.Run(fmt.Sprint(initialized), func(t *testing.T) {
			auth := newSharedClaudeOAuthAuth("claude-setup-race")
			if !initialized {
				auth.Metadata = nil
			}
			var wg sync.WaitGroup
			start := make(chan struct{})
			for i := 0; i < 16; i++ {
				wg.Add(1)
				go func(i int) {
					defer wg.Done()
					<-start
					for j := 0; j < 256; j++ {
						if i%2 == 0 {
							claudeauth.StoreMetadataValue(&auth.Metadata, "skip_account_profile", false)
							claudeauth.StoreMetadataValue(&auth.Metadata, "is_setup_token", false)
							claudeauth.StoreMetadataValue(&auth.Metadata, "setup_token", false)
							claudeauth.StoreMetadataString(&auth.Metadata, "account_uuid", "synthetic-profile")
						} else {
							_ = isClaudeSetupToken(auth, "sk-ant-oat-race-probe")
						}
					}
				}(i)
			}
			close(start)
			wg.Wait()
		})
	}
}

func TestClaudeExecutorSetupTokenMetadataFlags(t *testing.T) {
	for _, key := range []string{"skip_account_profile", "is_setup_token", "setup_token"} {
		t.Run(key, func(t *testing.T) {
			auth := newSharedClaudeOAuthAuth("claude-setup-flags")
			for _, value := range []any{false, "true", true} {
				claudeauth.StoreMetadataValue(&auth.Metadata, key, value)
				if got, want := isClaudeSetupToken(auth, "sk-ant-oat-race-probe"), value == true; got != want {
					t.Fatalf("flag %s=%v: got %v, want %v", key, value, got, want)
				}
			}
		})
	}
}
