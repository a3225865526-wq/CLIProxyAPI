//go:build !clearapi_staging_observability

package auth

import (
	"context"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
)

func poolObservationContext(ctx context.Context, _ cliproxyexecutor.Options) context.Context {
	return ctx
}
func poolObserveLease(*poolLease, string, string)                          {}
func poolObserveFence(*poolLease, bool, bool)                              {}
func (m *Manager) poolObserveResultLocked(context.Context, Result, string) {}
func (m *Manager) poolObservationSnapshot() any                            { return nil }
