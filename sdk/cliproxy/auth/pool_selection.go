package auth

import (
	"context"
	"time"

	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
)

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
	return manager.poolCandidateRejection(auth, model, opts) == ""
}

// poolCandidateRejection is shared by selection and read-only preflight.
func (manager *Manager) poolCandidateRejection(auth *Auth, model string, opts cliproxyexecutor.Options) string {
	if manager.poolGuard == nil {
		return ""
	}
	record, err := manager.poolGrants()
	if err != nil {
		return "pool_admission_unavailable"
	}
	return manager.poolCandidateRejectionFromRecord(record, auth, model, opts)
}

func (manager *Manager) poolCandidateRejectionFromRecord(record *PoolGrantFile, auth *Auth, model string, opts cliproxyexecutor.Options) string {
	if !manager.poolRegistrySupports(auth, model, record) {
		return "pool_registry_not_current"
	}
	caps, err := poolRequestCapabilities(cliproxyexecutor.Request{Payload: opts.OriginalRequest}, opts.Stream)
	if err != nil {
		return "request_capability_invalid"
	}
	resolved := manager.selectionModelForAuth(auth, model)
	if resolved == "" {
		resolved = model
	}
	if manager.poolModelCheck(record, auth, resolved, caps) != nil {
		return "pool_candidate_not_admitted"
	}
	return ""
}

// PoolPreflightResult intentionally excludes account identities and digests.
type PoolPreflightResult struct {
	EligibleCount int            `json:"eligible_count"`
	Rejections    map[string]int `json:"rejection_reasons"`
}

// PoolRequestPreflight observes admission without selecting, preparing or
// reserving an account. Execution still rechecks at its dispatch fence.
func (manager *Manager) PoolRequestPreflight(ctx context.Context, model string, opts cliproxyexecutor.Options) (PoolPreflightResult, error) {
	result := PoolPreflightResult{Rejections: make(map[string]int)}
	if manager.poolGuard == nil || manager.HomeEnabled() || manager.hasPluginScheduler() {
		return result, ErrPoolGuard
	}
	eligibility := authSelectionEligibilityForRequest(ctx, opts)
	pinned := pinnedAuthIDFromMetadata(opts.Metadata)
	manager.mu.RLock()
	defer manager.mu.RUnlock()
	record, err := manager.loadPoolGrants(true)
	if err != nil {
		return result, err
	}
	for _, candidate := range manager.auths {
		if candidate != nil && pinned != "" && candidate.ID != pinned {
			continue
		}
		if candidate == nil || candidate.Disabled || !eligibility.allows(candidate) {
			result.Rejections["auth_unavailable"]++
			continue
		}
		if _, ok := manager.executorLocked(executorKeyFromAuth(candidate)); !ok {
			result.Rejections["executor_not_found"]++
			continue
		}
		if reason := manager.poolCandidateRejectionFromRecord(record, candidate, model, opts); reason != "" {
			result.Rejections[reason]++
			continue
		}
		available, _, err := manager.availableAuthsForSelector(manager.selector, []*Auth{candidate}, "mixed", model, time.Now())
		if err != nil || len(available) == 0 {
			result.Rejections["auth_unavailable"]++
			continue
		}
		result.EligibleCount++
	}
	return result, nil
}
