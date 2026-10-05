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

// poolCandidateAllowed filters pool accounts during selection. Eligibility is
// decided solely on the account-resolved canonical model — the model the
// executor would actually dispatch — so a grant on the requested alias alone
// never admits a candidate. The requested name is observability and
// prefiltering input only. Execution-time begin and the dispatch fence re-check
// the final upstream model.
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
	resolved := manager.selectionModelForAuth(auth, model)
	if resolved == "" {
		resolved = model
	}
	return manager.poolModelCheck(record, auth, resolved, caps) == nil
}
