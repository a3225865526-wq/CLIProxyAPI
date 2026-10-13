//go:build !linux

package auth

import "fmt"

func syncManagementDirectory(string) error {
	return fmt.Errorf("management persistence: directory durability is not qualified on this platform")
}

func managementPersistenceQualified() bool { return false }
