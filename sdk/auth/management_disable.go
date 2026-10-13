package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
)

// ConfirmManagementDisable never rewrites or repairs the source. A mismatch or
// unqualified persistence barrier is an error, not a management commit.
func (s *FileTokenStore) ConfirmManagementDisable(_ context.Context, a *coreauth.Auth) error {
	if a == nil || a.Storage != nil || coreauth.IsPluginVirtualAuth(a) || coreauth.IsConfigAPIKeyAuth(a) {
		return fmt.Errorf("management disable: unsupported persistence path")
	}
	path, errPath := s.resolveAuthPath(a)
	if errPath != nil {
		return errPath
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	f, errOpen := os.OpenFile(path, os.O_RDWR, 0)
	if errOpen != nil {
		return errOpen
	}
	var metadata map[string]any
	errDecode := json.NewDecoder(f).Decode(&metadata)
	if errDecode != nil {
		_ = f.Close()
		return errDecode
	}
	disabled, valid := metadata["disabled"].(bool)
	management, validManagement := metadata[coreauth.ManagementDisabledKey].(bool)
	loaded := a.Clone()
	loaded.Metadata = metadata
	if !valid || !disabled || !validManagement || !management || coreauth.PoolCredentialDigest(loaded) != coreauth.PoolCredentialDigest(a) {
		_ = f.Close()
		return fmt.Errorf("management disable: durable identity/isolation mismatch")
	}
	errSync := f.Sync()
	if errClose := f.Close(); errSync == nil {
		errSync = errClose
	}
	if errSync != nil {
		return errSync
	}
	return syncManagementDirectory(filepath.Dir(path))
}
