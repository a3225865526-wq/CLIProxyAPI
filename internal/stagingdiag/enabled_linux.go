//go:build clearapi_staging_observability && linux

package stagingdiag

import (
	"errors"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

const Enabled = true

// Start is available only in explicitly tagged Linux staging artifacts.
// No route is registered on the main HTTP or management router.
func Start(read func() (any, error)) error {
	st, err := os.Lstat(grantPath)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return errors.New("staging diagnostic authorization unavailable")
	}
	owner, ok := st.Sys().(*syscall.Stat_t)
	if !ok || owner.Uid != 0 {
		return errors.New("staging diagnostic authorization owner invalid")
	}
	parent, err := os.Lstat(filepath.Dir(grantPath))
	if err != nil || !parent.IsDir() || parent.Mode().Perm() != 0700 {
		return errors.New("staging diagnostic authorization directory invalid")
	}
	directoryOwner, ok := parent.Sys().(*syscall.Stat_t)
	if !ok || directoryOwner.Uid != 0 {
		return errors.New("staging diagnostic authorization directory owner invalid")
	}
	g, err := loadGrant(grantPath)
	if err != nil {
		return errors.New("staging diagnostic authorization invalid")
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:19740")
	if err != nil {
		return errors.New("staging diagnostic loopback unavailable")
	}
	server := &http.Server{Handler: Handler(g.Key, time.Unix(g.Expires, 0), read, time.Now), ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 5 * time.Second, MaxHeaderBytes: 4096}
	go func() { _ = server.Serve(listener) }()
	// Expiry closes the listening socket as well as rejecting expired reads.
	time.AfterFunc(time.Until(time.Unix(g.Expires, 0)), func() { _ = server.Close() })
	return nil
}
