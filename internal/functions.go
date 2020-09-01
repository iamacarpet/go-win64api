// +build windows,amd64

package internal

import (
	"fmt"
	"os"
	"strings"
	"syscall"
	"unsafe"
)

// UTF16toString converts a pointer to a UTF16 string into a Go string.
func UTF16toString(p *uint16) string {
	return syscall.UTF16ToString((*[4096]uint16)(unsafe.Pointer(p))[:])
}

// GetResolved returns the full username in HOST\USER notation
func ResolveUsername(username string) (string, error) {
	if !strings.ContainsRune(username, '\\') {
		hn, err := os.Hostname()
		if err != nil {
			return "", fmt.Errorf("failed to get hostname: %s", err)
		}
		username = hn + `\` + username
	}
	return username, nil
}
