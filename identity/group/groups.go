// +build windows,amd64

package group

import (
	"fmt"
	"strings"
	"syscall"
	"unsafe"

	"github.com/iamacarpet/go-win64api/v2/internal"
	"github.com/iamacarpet/go-win64api/v2/internal/libraries/netapi32"

	so "github.com/iamacarpet/go-win64api/v2/shared"
)

var (
	Administrators = "Administrators"
	Users          = "Users"
)

// Add adds a new local group with the specified name and comment.
func Add(name, comment string) (bool, error) {
	var parmErr uint32
	var err error
	var gInfo netapi32.LOCALGROUP_INFO_1

	gInfo.Lgrpi1_name, err = syscall.UTF16PtrFromString(name)
	if err != nil {
		return false, fmt.Errorf("Unable to encode group name to UTF16: %s", err)
	}
	gInfo.Lgrpi1_comment, err = syscall.UTF16PtrFromString(comment)
	if err != nil {
		return false, fmt.Errorf("Unable to encode comment to UTF16: %s", err)
	}

	ret, _, _ := netapi32.NetLocalGroupAdd.Call(
		uintptr(0),                        // server name
		uintptr(uint32(1)),                // information level
		uintptr(unsafe.Pointer(&gInfo)),   // group information
		uintptr(unsafe.Pointer(&parmErr)), // error code out param
	)
	if ret != netapi32.NERR_Success {
		return false, syscall.Errno(ret)
	}
	return true, nil
}

// GetList enumerates the local groups defined on the system.
//
// If an error occurs in the call to the underlying NetLocalGroupEnum function, the
// returned error will be a syscall.Errno containing the error code.
// See: https://docs.microsoft.com/en-us/windows/desktop/api/lmaccess/nf-lmaccess-netlocalgroupenum
func GetList() ([]so.LocalGroup, error) {
	var (
		dataPointer  uintptr
		resumeHandle uintptr
		entriesRead  uint32
		entriesTotal uint32
		sizeTest     netapi32.LOCALGROUP_INFO_1
		retVal       = make([]so.LocalGroup, 0)
	)

	ret, _, _ := netapi32.NetLocalGroupEnum.Call(
		uintptr(0),                            // servername
		uintptr(uint32(1)),                    // level, LOCALGROUP_INFO_1
		uintptr(unsafe.Pointer(&dataPointer)), // struct buffer for output data.
		uintptr(uint32(netapi32.USER_MAX_PREFERRED_LENGTH)), // allow as much memory as required.
		uintptr(unsafe.Pointer(&entriesRead)),
		uintptr(unsafe.Pointer(&entriesTotal)),
		uintptr(unsafe.Pointer(&resumeHandle)),
	)
	if ret != netapi32.NERR_Success {
		return nil, syscall.Errno(ret)
	} else if dataPointer == uintptr(0) {
		return nil, fmt.Errorf("null pointer while fetching entry")
	}
	defer netapi32.NetApiBufferFree.Call(dataPointer)

	var iter = dataPointer
	for i := uint32(0); i < entriesRead; i++ {
		var data = (*netapi32.LOCALGROUP_INFO_1)(unsafe.Pointer(iter))

		gd := so.LocalGroup{
			Name:    internal.UTF16toString(data.Lgrpi1_name),
			Comment: internal.UTF16toString(data.Lgrpi1_comment),
		}
		retVal = append(retVal, gd)

		iter = uintptr(unsafe.Pointer(iter + unsafe.Sizeof(sizeTest)))
	}

	return retVal, nil
}

// Delete deletes the specified local group.
//
// If an error occurs in the call to the underlying NetLocalGroupDel function, the
// returned error will be a syscall.Errno containing the error code.
// See: https://docs.microsoft.com/en-us/windows/desktop/api/lmaccess/nf-lmaccess-netlocalgroupdel
func Delete(name string) (bool, error) {
	namePtr, err := syscall.UTF16PtrFromString(name)
	if err != nil {
		return false, fmt.Errorf("Unable to encode group name to UTF16: %s", err)
	}

	ret, _, _ := netapi32.NetLocalGroupDel.Call(
		uintptr(0), // servername
		uintptr(unsafe.Pointer(namePtr)),
	)
	if ret != netapi32.NERR_Success {
		return false, syscall.Errno(ret)
	}
	return true, nil
}

// GetMembers returns information about the members of the specified
// local group.
//
// If an error occurs in the call to the underlying NetLocalGroupGetMembers function, the
// returned error will be a syscall.Errno containing the error code.
// See: https://docs.microsoft.com/en-us/windows/desktop/api/lmaccess/nf-lmaccess-netlocalgroupgetmembers
func GetMembers(groupname string) ([]so.LocalGroupMember, error) {
	var (
		dataPointer  uintptr
		resumeHandle uintptr
		entriesRead  uint32
		entriesTotal uint32
		sizeTest     netapi32.LOCALGROUP_MEMBERS_INFO_3
		retVal       []so.LocalGroupMember = make([]so.LocalGroupMember, 0)
	)

	groupnamePtr, err := syscall.UTF16PtrFromString(groupname)
	if err != nil {
		return nil, fmt.Errorf("Unable to encode group name to UTF16: %s", err)
	}

	ret, _, _ := netapi32.NetLocalGroupGetMembers.Call(
		uintptr(0),                            // servername
		uintptr(unsafe.Pointer(groupnamePtr)), // group name
		uintptr(3),                            // level, LOCALGROUP_MEMBERS_INFO_3
		uintptr(unsafe.Pointer(&dataPointer)), // bufptr
		uintptr(uint32(netapi32.USER_MAX_PREFERRED_LENGTH)), // prefmaxlen
		uintptr(unsafe.Pointer(&entriesRead)),               // entriesread
		uintptr(unsafe.Pointer(&entriesTotal)),              // totalentries
		uintptr(unsafe.Pointer(&resumeHandle)),              // resumehandle
	)
	if ret != netapi32.NERR_Success {
		return nil, syscall.Errno(ret)
	} else if dataPointer == uintptr(0) {
		return nil, fmt.Errorf("null pointer while fetching entry")
	}
	defer netapi32.NetApiBufferFree.Call(dataPointer)

	var iter = dataPointer
	for i := uint32(0); i < entriesRead; i++ {
		var data = (*netapi32.LOCALGROUP_MEMBERS_INFO_3)(unsafe.Pointer(iter))

		domainAndUsername := internal.UTF16toString(data.Lgrmi3_domainandname)
		split := strings.SplitN(domainAndUsername, "\\", 1)
		var domain, name string
		if len(split) > 1 {
			domain = split[0]
			name = split[1]
		} else {
			// This really shouldn't happen, but just in case...
			name = split[0]
		}

		gd := so.LocalGroupMember{
			Domain:        domain,
			Name:          name,
			DomainAndName: domainAndUsername,
		}
		retVal = append(retVal, gd)

		iter = uintptr(unsafe.Pointer(iter + unsafe.Sizeof(sizeTest)))
	}

	return retVal, nil
}

// AddMember adds the user as a member of the specified group.
func AddMember(groupname, username string) (bool, error) {
	username, err := internal.ResolveUsername(username)
	if err != nil {
		return false, err
	}
	uPointer, err := syscall.UTF16PtrFromString(username)
	if err != nil {
		return false, fmt.Errorf("Unable to encode username to UTF16")
	}
	gPointer, err := syscall.UTF16PtrFromString(groupname)
	if err != nil {
		return false, fmt.Errorf("unable to encode group name to UTF16")
	}
	var uArray = make([]netapi32.LOCALGROUP_MEMBERS_INFO_3, 1)
	uArray[0] = netapi32.LOCALGROUP_MEMBERS_INFO_3{
		Lgrmi3_domainandname: uPointer,
	}
	ret, _, _ := netapi32.NetLocalGroupAddMembers.Call(
		uintptr(0),                          // servername
		uintptr(unsafe.Pointer(gPointer)),   // group name
		uintptr(uint32(3)),                  // level
		uintptr(unsafe.Pointer(&uArray[0])), // user array.
		uintptr(uint32(len(uArray))),
	)
	if ret != netapi32.NERR_Success {
		return false, fmt.Errorf("unable to process. %d", ret)
	}
	return true, nil
}

// AddMembers adds the specified members to the group, if they are not
// already members.
//
// If an error occurs in the call to the underlying NetLocalGroupAddMembers function, the
// returned error will be a syscall.Errno containing the error code.
// See: https://docs.microsoft.com/en-us/windows/desktop/api/lmaccess/nf-lmaccess-netlocalgroupaddmembers
func AddMembers(groupname string, usernames []string) (bool, error) {
	return modMembers(netapi32.NetLocalGroupAddMembers, groupname, usernames)
}

// RemoveMember removes the user from the specified group.
func RemoveMember(groupname, username string) (bool, error) {
	username, err := internal.ResolveUsername(username)
	if err != nil {
		return false, err
	}
	uPointer, err := syscall.UTF16PtrFromString(username)
	if err != nil {
		return false, fmt.Errorf("unable to encode username to UTF16")
	}
	gPointer, err := syscall.UTF16PtrFromString(groupname)
	if err != nil {
		return false, fmt.Errorf("unable to encode group name to UTF16")
	}
	var uArray = make([]netapi32.LOCALGROUP_MEMBERS_INFO_3, 1)
	uArray[0] = netapi32.LOCALGROUP_MEMBERS_INFO_3{
		Lgrmi3_domainandname: uPointer,
	}
	ret, _, _ := netapi32.NetLocalGroupDelMembers.Call(
		uintptr(0),                          // servername
		uintptr(unsafe.Pointer(gPointer)),   // group name
		uintptr(uint32(3)),                  // level
		uintptr(unsafe.Pointer(&uArray[0])), // user array.
		uintptr(uint32(len(uArray))),
	)
	if ret != netapi32.NERR_Success {
		return false, fmt.Errorf("unable to process. %d", ret)
	}
	return true, nil
}

// RemoveMembers removes the specified members from the local group.
//
// If an error occurs in the call to the underlying NetLocalGroupDelMembers function, the
// returned error will be a syscall.Errno containing the error code.
// See: https://docs.microsoft.com/en-us/windows/desktop/api/lmaccess/nf-lmaccess-netlocalgroupdelmembers
func RemoveMembers(groupname string, usernames []string) (bool, error) {
	return modMembers(netapi32.NetLocalGroupDelMembers, groupname, usernames)
}

// SetMembers sets the membership of the group to contain exactly the
// set of users specified in usernames.
//
// If an error occurs in the call to the underlying NetLocalGroupSetMembers function, the
// returned error will be a syscall.Errno containing the error code.
// See: https://docs.microsoft.com/en-us/windows/desktop/api/lmaccess/nf-lmaccess-netlocalgroupsetmembers
func SetMembers(groupname string, usernames []string) (bool, error) {
	return modMembers(netapi32.NetLocalGroupSetMembers, groupname, usernames)
}

func modMembers(proc *syscall.LazyProc, groupname string, usernames []string) (bool, error) {
	memberInfos := make([]netapi32.LOCALGROUP_MEMBERS_INFO_3, 0, len(usernames))

	groupnamePtr, err := syscall.UTF16PtrFromString(groupname)
	if err != nil {
		return false, fmt.Errorf("Unable to encode group name to UTF16: %s", err)
	}

	for _, username := range usernames {
		username, err = internal.ResolveUsername(username)
		if err != nil {
			return false, err
		}
		namePtr, err := syscall.UTF16PtrFromString(username)
		if err != nil {
			return false, fmt.Errorf("Unable to encode username to UTF16: %s", err)
		}
		memberInfos = append(memberInfos, netapi32.LOCALGROUP_MEMBERS_INFO_3{
			Lgrmi3_domainandname: namePtr,
		})
	}

	if len(memberInfos) == 0 {
		// Add a fake entry just so that the slice isn't empty, so we can take
		// the address of the first entry
		memberInfos = append(memberInfos, netapi32.LOCALGROUP_MEMBERS_INFO_3{})
	}

	ret, _, _ := proc.Call(
		uintptr(0),                               // servername
		uintptr(unsafe.Pointer(groupnamePtr)),    // group name
		uintptr(3),                               // level, LOCALGROUP_MEMBERS_INFO_3
		uintptr(unsafe.Pointer(&memberInfos[0])), // buf
		uintptr(len(usernames)),                  // totalEntries
	)
	if ret != netapi32.NERR_Success {
		return false, syscall.Errno(ret)
	}

	return true, nil
}
