package auth

import (
	"context"

	"github.com/gin-gonic/gin"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
)

// isControlledImagesRequest reports whether this execution must take the
// single-account images path. It requires all three of: the images feature,
// a signed policy header set, and either the images path metadata or the
// images-specific request header.
func (m *Manager) isControlledImagesRequest(ctx context.Context, providers []string, opts cliproxyexecutor.Options) bool {
	if !imagesModeEnabled() || len(providers) != 1 || providers[0] != "codex" {
		return false
	}
	headers := opts.Headers
	if ctx != nil {
		if c, ok := ctx.Value("gin").(*gin.Context); ok && c != nil && c.Request != nil {
			headers = c.Request.Header
		}
	}
	if headers == nil || headers.Get(pg03ImagesPolicyHeader) == "" {
		return false
	}
	path, _ := opts.Metadata[cliproxyexecutor.RequestPathMetadataKey].(string)
	return path == pg03ImagesPath || headers.Get(pg03ImagesRequestHeader) != ""
}

// executeControlledImages runs one controlled image generation. Unlike the
// generic mixed loop it never rotates credentials: the signed policy names the
// only account this attempt may use, and a second account would be a second
// provider dispatch the Gateway cannot authorize.
func (m *Manager) executeControlledImages(ctx context.Context, provider string, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
	policy, ids, err := m.verifyPG03ImagesPolicy(ctx, []string{provider}, opts)
	if err != nil {
		return cliproxyexecutor.Response{}, wrapRequestStopError(err)
	}
	if policy == nil || len(ids) == 0 {
		return cliproxyexecutor.Response{}, wrapRequestStopError(ErrPoolGuard)
	}
	ctx = withPG03ImagesPolicy(ctx, policy)
	opts.EnsureMetadata()
	opts.Metadata[cliproxyexecutor.PinnedAuthMetadataKey] = ids[0]

	executor, ok := m.executorLocked("codex")
	if !ok {
		return cliproxyexecutor.Response{}, &Error{Code: "executor_not_found", Message: "executor not registered"}
	}
	auth, ok := m.GetByID(ids[0])
	if !ok || auth == nil {
		return cliproxyexecutor.Response{}, wrapRequestStopError(ErrPoolGuard)
	}
	execCtx := contextWithRequestedModelAlias(ctx, opts, authSelectionModelFromOptions(opts, req.Model))
	execCtx = newUpstreamAttemptContext(execCtx)
	response, errExec := executorForAuth(executor, auth).Execute(execCtx, auth, req, opts)
	errExec = markUpstreamExecutionAttemptFromContext(execCtx, errExec)
	if errExec != nil {
		return cliproxyexecutor.Response{}, errExec
	}
	return response, nil
}
