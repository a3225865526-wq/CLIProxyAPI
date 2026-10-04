//go:build !darwin && !dragonfly && !freebsd && !linux && !netbsd && !openbsd && !windows

package auth

import "os"

func lockPoolCheckpoint(*os.File) error { return ErrPoolGuard }
func unlockPoolCheckpoint(*os.File)     {}
