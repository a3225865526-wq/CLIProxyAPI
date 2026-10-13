package auth

import (
	"errors"
	"net/http"
)

// localModelResolutionError is constructed only before auth manager execution.
// It proves that this resolver invocation did not reach a provider transport.
type localModelResolutionError struct{ body string }

func NewLocalModelResolutionError(body string) error { return &localModelResolutionError{body: body} }
func (e *localModelResolutionError) Error() string   { return e.body }
func (*localModelResolutionError) StatusCode() int   { return http.StatusBadRequest }

func IsLocalModelResolutionError(err error) bool {
	var local *localModelResolutionError
	return !IsTerminalAuthError(err) && !hasUpstreamExecutionAttempt(err) && errors.As(err, &local)
}
