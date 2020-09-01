// +build windows,amd64

package kernel32

import "syscall"

var (
	modKernel32 = syscall.NewLazyDLL("kernel32.dll")

	LocalFree = modKernel32.NewProc("LocalFree")
)
