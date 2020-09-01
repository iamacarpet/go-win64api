// +build windows,amd64

package internal

import (
	"syscall"
	"unsafe"
)

// UTF16toString converts a pointer to a UTF16 string into a Go string.
func UTF16toString(p *uint16) string {
	return syscall.UTF16ToString((*[4096]uint16)(unsafe.Pointer(p))[:])
}
