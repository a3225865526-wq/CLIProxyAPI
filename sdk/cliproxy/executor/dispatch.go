package executor

import "context"

type dispatchGuardKey struct{}

// DispatchGuard authorizes the initiation of an upstream transport operation.
// Its linearization point precedes network I/O; it cannot certify remote receipt.
type DispatchGuard interface{ AuthorizeDispatch() error }

func WithDispatchGuard(ctx context.Context, guard DispatchGuard) context.Context {
	return context.WithValue(ctx, dispatchGuardKey{}, guard)
}

func BeforeUpstreamDispatch(ctx context.Context) error {
	if ctx == nil {
		return nil
	}
	if err := ctx.Err(); err != nil {
		return context.Cause(ctx)
	}
	if guard, ok := ctx.Value(dispatchGuardKey{}).(DispatchGuard); ok {
		return guard.AuthorizeDispatch()
	}
	return nil
}

// GuardedDispatch forbids transport replay inside a pool execution attempt.
func GuardedDispatch(ctx context.Context) bool {
	if ctx == nil {
		return false
	}
	_, ok := ctx.Value(dispatchGuardKey{}).(DispatchGuard)
	return ok
}

// BeforeUpstreamConnect fences a credential-bearing websocket handshake.
// A following payload send must independently revalidate the same lease.
func BeforeUpstreamConnect(ctx context.Context) error {
	if ctx == nil {
		return nil
	}
	if err := ctx.Err(); err != nil {
		return context.Cause(ctx)
	}
	if guard, ok := ctx.Value(dispatchGuardKey{}).(interface{ AuthorizeConnect() error }); ok {
		return guard.AuthorizeConnect()
	}
	if GuardedDispatch(ctx) {
		return BeforeUpstreamDispatch(ctx)
	}
	return nil
}
