package auth

import cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"

func firstPoolGrantModel(manager *Manager, auth *Auth) string {
	if auth == nil || manager.poolGuard == nil {
		return ""
	}
	record, err := manager.poolGuard.grants()
	if err != nil {
		return ""
	}
	for _, grant := range record.Grants {
		if grant.AuthID == auth.ID && len(grant.Models) > 0 {
			return grant.Models[0]
		}
	}
	return ""
}

func (manager *Manager) poolCandidateAllowed(auth *Auth, model string, opts cliproxyexecutor.Options) bool {
	if manager.poolGuard == nil {
		return true
	}
	caps, err := poolRequestCapabilities(cliproxyexecutor.Request{Payload: opts.OriginalRequest}, opts.Stream)
	if err != nil {
		return false
	}
	_, err = manager.poolGrant(auth, model, caps)
	return err == nil
}
