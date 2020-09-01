// +build windows,amd64

package netapi32

import "syscall"

var (
	modNetapi32 = syscall.NewLazyDLL("netapi32.dll")

	NetApiBufferFree = modNetapi32.NewProc("NetApiBufferFree")
)

const (
	ERROR_ACCESS_DENIED               syscall.Errno = 5 // 0x00000005
	ERROR_NOT_ENOUGH_MEMORY           syscall.Errno = 8
	ERROR_INVALID_PARAMETER           syscall.Errno = 87
	ERROR_INVALID_NAME                syscall.Errno = 123
	ERROR_INVALID_LEVEL               syscall.Errno = 124
	ERROR_MORE_DATA                   syscall.Errno = 234
	ERROR_SESSION_CREDENTIAL_CONFLICT syscall.Errno = 1219

	RPC_S_SERVER_UNAVAILABLE = 2147944122
	RPC_E_REMOTE_DISABLED    = 2147549468
)
