// +build windows,amd64

package advapi32

import "syscall"

var (
	modAdvapi32 = syscall.NewLazyDLL("advapi32.dll")
)
