package auth

import (
	"context"

	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
)

// definitiveUpstreamRejection recognizes only typed local zero-dispatch
// provenance. A provider status code or response body is not such proof.
func definitiveUpstreamRejection(err error) bool {
	return IsLocalModelResolutionError(err) || IsLocalPoolSelectionError(err)
}

// isPoolAttemptContext reports whether ctx belongs to a pool-guarded request.
// poolExecutionContext stamps this marker on every pool request before any
// candidate attempt runs.
func isPoolAttemptContext(ctx context.Context) bool {
	if ctx == nil {
		return false
	}
	budget, _ := ctx.Value(poolAttemptContextKey{}).(*atomicPoolAttempt)
	return budget != nil
}

// mustStopReplayAfterDispatch decides whether a failed attempt must terminate
// the request instead of being transparently replayed on another credential.
//
// Pool traffic only: pool accounts are shared, metered upstream identities, so
// once an attempt reached the transport boundary the upstream may already have
// executed (and billed for) the request even though no output or usage came
// back. Replaying such an attempt would hide that cost. A generic response,
// including a 400, 401, 403, 404, 429, or model_not_found body, therefore
// stops replay.
// Non-pool traffic keeps its established failover contract; observed upstream
// output still stops codex replay for every codex request.
func mustStopReplayAfterDispatch(ctx context.Context, provider string, err error) bool {
	if err == nil {
		return false
	}
	if isPoolAttemptContext(ctx) {
		if cliproxyexecutor.UpstreamWorkObserved(ctx) {
			return true
		}
		if cliproxyexecutor.UpstreamAttempted(ctx) || hasUpstreamExecutionAttempt(err) {
			// A local error cannot erase an already observed transport attempt.
			return true
		}
		return false
	}
	return provider == "codex" && cliproxyexecutor.UpstreamWorkObserved(ctx)
}
