package auth

import "errors"

// poolSelectionError can only originate from local admission before execution.
type poolSelectionError struct{ cause *Error }

// NewPoolSelectionError constructs the executor's local zero-dispatch rejection.
func NewPoolSelectionError() error {
	return &poolSelectionError{&Error{Code: "pool_no_eligible_account", Message: "no pool account admitted for model", HTTPStatus: 503}}
}

// IsLocalPoolSelectionError rejects terminal and provider-attempt wrappers even
// when their error chain contains the same structured code.
func IsLocalPoolSelectionError(err error) bool {
	var local *poolSelectionError
	return !IsTerminalAuthError(err) && !hasUpstreamExecutionAttempt(err) && errors.As(err, &local)
}

func (e *poolSelectionError) Error() string   { return e.cause.Error() }
func (e *poolSelectionError) StatusCode() int { return e.cause.StatusCode() }
func (e *poolSelectionError) Unwrap() error   { return e.cause }
