package auth

import (
	"context"
	"net/http"

	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
)

// definitiveUpstreamRejection reports whether err is a clean upstream
// client-error response. Such a response proves the upstream refused the
// request before executing it, so replaying the request on another credential
// cannot make the upstream consume twice. 408 is excluded: it reports a
// server-side timeout that does not prove the request went unprocessed.
func definitiveUpstreamRejection(err error) bool {
	if err == nil {
		return false
	}
	code := statusCodeFromError(err)
	return code >= 400 && code < 500 && code != http.StatusRequestTimeout
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
// back. Replaying such an attempt would hide that cost, so replay is only
// allowed when the upstream answered with a definitive pre-execution
// rejection (4xx). Non-pool traffic keeps its established failover contract;
// observed upstream output still stops codex replay for every codex request.
func mustStopReplayAfterDispatch(ctx context.Context, provider string, err error) bool {
	if err == nil {
		return false
	}
	if isPoolAttemptContext(ctx) {
		if cliproxyexecutor.UpstreamWorkObserved(ctx) {
			return true
		}
		if cliproxyexecutor.UpstreamAttempted(ctx) {
			return !definitiveUpstreamRejection(err)
		}
		return false
	}
	return provider == "codex" && cliproxyexecutor.UpstreamWorkObserved(ctx)
}
