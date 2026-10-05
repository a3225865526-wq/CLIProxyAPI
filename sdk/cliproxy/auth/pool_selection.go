package auth

import cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"

func firstPoolGrantModel(manager *Manager, auth *Auth) string {
	if auth == nil || manager.poolGuard == nil {
		return ""
	}
	record, err := manager.poolGrants()
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

// requestedModelFromOptions recovers the client-requested model for observability.
func requestedModelFromOptions(opts cliproxyexecutor.Options) string {
	if opts.Metadata == nil {
		return ""
	}
	requested, _ := opts.Metadata[cliproxyexecutor.RequestedModelMetadataKey].(string)
	return requested
}

// poolCandidateAllowed filters pool accounts during selection. The check runs on
// the requested model and, if that differs, on the account-resolved canonical
// model, so an alias can never select an account whose canonical model is not
// admitted. Execution-time begin and the dispatch fence re-check the final model.
func (manager *Manager) poolCandidateAllowed(auth *Auth, model string, opts cliproxyexecutor.Options) bool {
	if manager.poolGuard == nil {
		return true
	}
	caps, err := poolRequestCapabilities(cliproxyexecutor.Request{Payload: opts.OriginalRequest}, opts.Stream)
	if err != nil {
		return false
	}
	record, err := manager.poolGrants()
	if err != nil {
		return false
	}
	if err := manager.poolModelCheck(record, auth, model, caps); err == nil {
		return true
	}
	resolved := manager.selectionModelForAuth(auth, model)
	if resolved == "" || resolved == model {
		return false
	}
	return manager.poolModelCheck(record, auth, resolved, caps) == nil
}
