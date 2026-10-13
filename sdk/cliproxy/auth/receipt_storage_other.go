//go:build !linux

package auth

import (
	"errors"
	"os"
)

func openReceiptDirectory(string) (*os.File, error) {
	return nil, errors.New("transport receipts require Linux process and permission attestation")
}

func openReceiptFile(*os.File, string, bool) (*os.File, error) {
	return nil, errors.New("transport receipts require Linux")
}
