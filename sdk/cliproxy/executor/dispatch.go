package executor

import (
	"context"
	"net/http"
)

func LocalAccountUnavailable(ctx context.Context) error {
	if guard, ok := ctx.Value(dispatchGuardKey{}).(interface{ LocalAccountUnavailable() error }); ok {
		return guard.LocalAccountUnavailable()
	}
	return context.Canceled
}

func ResponsesSSE(ctx context.Context) bool {
	guard, ok := ctx.Value(dispatchGuardKey{}).(interface{ ResponsesSSE() bool })
	return ok && guard.ResponsesSSE()
}

func PersistResponsesSSEEvent(ctx context.Context, payload []byte) error {
	if guard, ok := ctx.Value(dispatchGuardKey{}).(interface{ PersistResponsesSSEEvent([]byte) error }); ok {
		return guard.PersistResponsesSSEEvent(payload)
	}
	return nil
}

// PersistImagesResult is the images analogue of PersistResponsesSSEEvent: the
// lease makes the payload durable before any success terminal is reported.
func PersistImagesResult(ctx context.Context, payload []byte, requested int) error {
	if guard, ok := ctx.Value(dispatchGuardKey{}).(interface {
		PersistImagesResult([]byte, int) error
	}); ok {
		return guard.PersistImagesResult(payload, requested)
	}
	return nil
}

type dispatchGuardKey struct{}

// DispatchGuard authorizes the initiation of an upstream transport operation.
// Its linearization point precedes network I/O; it cannot certify remote receipt.
type DispatchGuard interface{ AuthorizeDispatch() error }

// DispatchObserver records the point immediately before transport I/O. The
// observer may fail closed; callers must not send after that failure.
type DispatchObserver interface{ UpstreamDispatchStarted() error }

func WithDispatchGuard(ctx context.Context, guard DispatchGuard) context.Context {
	return context.WithValue(ctx, dispatchGuardKey{}, guard)
}

func BeforeUpstreamDispatch(ctx context.Context, request ...*http.Request) error {
	if ctx == nil {
		return nil
	}
	if err := ctx.Err(); err != nil {
		return context.Cause(ctx)
	}
	if guard, ok := ctx.Value(dispatchGuardKey{}).(DispatchGuard); ok {
		if len(request) != 0 {
			if validator, ok := guard.(interface{ ValidateDispatchProtocol(*http.Request) error }); ok {
				if err := validator.ValidateDispatchProtocol(request[0]); err != nil {
					return err
				}
			}
		}
		return guard.AuthorizeDispatch()
	}
	return nil
}

// MarkUpstreamDispatchStarted records the trusted transport boundary, after
// authorization and immediately before the underlying network operation.
func MarkUpstreamDispatchStarted(ctx context.Context) error {
	if ctx == nil {
		return nil
	}
	if observer, ok := ctx.Value(dispatchGuardKey{}).(DispatchObserver); ok {
		return observer.UpstreamDispatchStarted()
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
