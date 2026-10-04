//go:build darwin || dragonfly || freebsd || linux || netbsd || openbsd

package auth

import (
	"os"

	"golang.org/x/sys/unix"
)

func lockPoolCheckpoint(file *os.File) error {
	return unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB)
}
func unlockPoolCheckpoint(file *os.File) { _ = unix.Flock(int(file.Fd()), unix.LOCK_UN) }
