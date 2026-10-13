//go:build darwin || dragonfly || freebsd || linux || netbsd || openbsd

package auth

import (
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

func lockPoolCheckpoint(file *os.File) error {
	return unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB)
}
func unlockPoolCheckpoint(file *os.File) { _ = unix.Flock(int(file.Fd()), unix.LOCK_UN) }

func replacePoolPolicy(source, target string) error {
	if err := os.Rename(source, target); err != nil {
		return err
	}
	directory, err := os.Open(filepath.Dir(target))
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}
