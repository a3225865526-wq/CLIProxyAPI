//go:build !clearapi_staging_observability || !linux

package stagingdiag

const Enabled = false

// Start never enables diagnostics in an ordinary product build.
func Start(func() (any, error)) error { return nil }
