//go:build linux

package auth

import "os"

func syncManagementDirectory(path string) error {
	dir, errOpen := os.Open(path)
	if errOpen != nil {
		return errOpen
	}
	errSync := dir.Sync()
	if errClose := dir.Close(); errSync == nil {
		errSync = errClose
	}
	return errSync
}

func managementPersistenceQualified() bool { return true }
