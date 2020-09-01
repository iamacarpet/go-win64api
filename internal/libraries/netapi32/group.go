package netapi32

import "syscall"

var (
	NetLocalGroupAdd        = modNetapi32.NewProc("NetLocalGroupAdd")
	NetLocalGroupEnum       = modNetapi32.NewProc("NetLocalGroupEnum")
	NetLocalGroupDel        = modNetapi32.NewProc("NetLocalGroupDel")
	NetLocalGroupSetMembers = modNetapi32.NewProc("NetLocalGroupSetMembers")
	NetLocalGroupGetMembers = modNetapi32.NewProc("NetLocalGroupGetMembers")
	NetLocalGroupAddMembers = modNetapi32.NewProc("NetLocalGroupAddMembers")
	NetLocalGroupDelMembers = modNetapi32.NewProc("NetLocalGroupDelMembers")
)

// Possible errors returned by local group management functions
// Error code enumerations taken from MS-ERREF documentation:
// https://msdn.microsoft.com/en-us/library/cc231196.aspx
const (
	NERR_GroupNotFound syscall.Errno = 2220 // 0x000008AC

	ERROR_MEMBER_NOT_IN_ALIAS syscall.Errno = 1377 // 0x00000561
	ERROR_MEMBER_IN_ALIAS     syscall.Errno = 1378 // 0x00000562
	ERROR_NO_SUCH_MEMBER      syscall.Errno = 1387 // 0x0000056B
	ERROR_INVALID_MEMBER      syscall.Errno = 1388 // 0x0000056C
)

// LOCALGROUP_INFO_0 represents level 0 information about local Windows groups.
// This struct matches the struct definition in the Windows headers (lmaccess.h).
type LOCALGROUP_INFO_0 struct {
	Lgrpi0_name *uint16 // UTF-16 group name
}

// LOCALGROUP_INFO_1 represents level 1 information about local Windows groups.
// This struct matches the struct definition in the Windows headers (lmaccess.h).
type LOCALGROUP_INFO_1 struct {
	Lgrpi1_name    *uint16 // UTF-16 group name
	Lgrpi1_comment *uint16 // UTF-16 group comment
}
