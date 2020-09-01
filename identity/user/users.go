// +build windows,amd64

package user

import (
	"fmt"
	"syscall"
	"time"
	"unsafe"

	"github.com/iamacarpet/go-win64api/v2/identity/group"

	"github.com/iamacarpet/go-win64api/v2/internal"
	"github.com/iamacarpet/go-win64api/v2/internal/libraries/netapi32"

	so "github.com/iamacarpet/go-win64api/v2/shared"
)

// AddOptions contains extended options for creating a new user account.
//
// The only required fields are Username and Password.
//
// Fields:
//	- Username		account username, limited to 20 characters.
//	- Password 		account password
//	- FullName		user's full name (default: none)
//  - PrivLevel		account's prvilege level, must be one of the USER_PRIV_* constants
//					(default: USER_PRIV_GUEST)
// 	- HomeDir		If non-empty, the user's home directory is set to the specified
//					path.
//	- Comment		A comment to associate with the account (default: none)
//	- ScriptPath 	If non-empty, the path to the user's logon script file, which can
//					be a .CMD, .EXE, or .BAT file. (default: none)
type AddOptions struct {
	// Required
	Username string
	Password string

	// Optional
	FullName   string
	PrivLevel  uint32
	HomeDir    string
	Comment    string
	ScriptPath string
}

// AddEx creates a new user account.
// As opposed to the simpler UserAdd, UserAddEx allows specification of full
// level 1 information while creating a user.
func AddEx(opts AddOptions) (bool, error) {
	var parmErr uint32
	var err error
	uInfo := netapi32.USER_INFO_1{
		Usri1_priv:  opts.PrivLevel,
		Usri1_flags: netapi32.USER_UF_SCRIPT | netapi32.USER_UF_NORMAL_ACCOUNT | netapi32.USER_UF_DONT_EXPIRE_PASSWD,
	}
	uInfo.Usri1_name, err = syscall.UTF16PtrFromString(opts.Username)
	if err != nil {
		return false, fmt.Errorf("Unable to encode username to UTF16: %s", err)
	}
	uInfo.Usri1_password, err = syscall.UTF16PtrFromString(opts.Password)
	if err != nil {
		return false, fmt.Errorf("Unable to encode password to UTF16: %s", err)
	}
	if opts.Comment != "" {
		uInfo.Usri1_comment, err = syscall.UTF16PtrFromString(opts.Comment)
		if err != nil {
			return false, fmt.Errorf("Unable to encode comment to UTF16: %s", err)
		}
	}
	if opts.HomeDir != "" {
		uInfo.Usri1_home_dir, err = syscall.UTF16PtrFromString(opts.HomeDir)
		if err != nil {
			return false, fmt.Errorf("Unable to encode home directory path to UTF16: %s", err)
		}
	}
	if opts.ScriptPath != "" {
		uInfo.Usri1_script_path, err = syscall.UTF16PtrFromString(opts.HomeDir)
		if err != nil {
			return false, fmt.Errorf("Unable to encode script path to UTF16: %s", err)
		}
	}
	ret, _, _ := netapi32.NetUserAdd.Call(
		uintptr(0),
		uintptr(uint32(1)),
		uintptr(unsafe.Pointer(&uInfo)),
		uintptr(unsafe.Pointer(&parmErr)),
	)
	if ret != netapi32.NERR_Success {
		return false, fmt.Errorf("Unable to process: status=%d error=%d", ret, parmErr)
	}
	if opts.FullName != "" {
		ok, err := SetFullname(opts.Username, opts.FullName)
		if err != nil {
			return false, fmt.Errorf("Unable to set full name: %s", err)
		}
		if !ok {
			return false, fmt.Errorf("Problem while setting Full Name")
		}
	}

	return group.AddMember(group.Users, opts.Username)
}

// Add creates a new user account with the given username, full name, and
// password.
// The new account will have the standard User privilege level.
func Add(username string, fullname string, password string) (bool, error) {
	return AddEx(AddOptions{
		Username:  username,
		Password:  password,
		FullName:  fullname,
		PrivLevel: netapi32.USER_PRIV_USER,
	})
}

// Delete deletes the user with the given username.
func Delete(username string) (bool, error) {
	uPointer, err := syscall.UTF16PtrFromString(username)
	if err != nil {
		return false, fmt.Errorf("Unable to encode username to UTF16")
	}
	ret, _, _ := netapi32.NetUserDel.Call(
		uintptr(0),
		uintptr(unsafe.Pointer(uPointer)),
	)
	if ret != netapi32.NERR_Success {
		return false, fmt.Errorf("Unable to process. %d", ret)
	}
	return true, nil
}

// IsAdminLocal returns whether the user with the specified user name has
// administration rights on the local machine.
func IsAdminLocal(username string) (bool, error) {
	var dataPointer uintptr
	uPointer, err := syscall.UTF16PtrFromString(username)
	if err != nil {
		return false, fmt.Errorf("unable to encode username to UTF16")
	}
	_, _, _ = netapi32.NetUserGetInfo.Call(
		uintptr(0),                            // servername
		uintptr(unsafe.Pointer(uPointer)),     // username
		uintptr(uint32(1)),                    // level, request USER_INFO_1
		uintptr(unsafe.Pointer(&dataPointer)), // Pointer to struct.
	)
	defer netapi32.NetApiBufferFree.Call(dataPointer)

	if dataPointer == uintptr(0) {
		return false, fmt.Errorf("unable to get data structure")
	}

	var data = (*netapi32.USER_INFO_1)(unsafe.Pointer(dataPointer))

	if data.Usri1_priv == netapi32.USER_PRIV_ADMIN {
		return true, nil
	} else {
		return false, nil
	}
}

// IsAdminActiveDirectory returns whether the specified user is an administrator for
// the specified domain.
func IsAdminActiveDirectory(username string, domain string) (bool, error) {
	var dataPointer uintptr
	var dcPointer uintptr
	uPointer, err := syscall.UTF16PtrFromString(username)
	if err != nil {
		return false, fmt.Errorf("unable to encode username to UTF16")
	}
	dPointer, err := syscall.UTF16PtrFromString(domain)
	if err != nil {
		return false, fmt.Errorf("unable to encode domain to UTF16")
	}

	_, _, _ = netapi32.NetGetAnyDCName.Call(
		uintptr(0),                        // servername
		uintptr(unsafe.Pointer(dPointer)), // domainame
		uintptr(unsafe.Pointer(&dcPointer)),
	)
	defer netapi32.NetApiBufferFree.Call(dcPointer)

	_, _, _ = netapi32.NetUserGetInfo.Call(
		uintptr(dcPointer),                    // servername
		uintptr(unsafe.Pointer(uPointer)),     // username
		uintptr(uint32(1)),                    // level, request USER_INFO_1
		uintptr(unsafe.Pointer(&dataPointer)), // Pointer to struct.
	)
	defer netapi32.NetApiBufferFree.Call(dataPointer)

	if dataPointer == uintptr(0) {
		return false, fmt.Errorf("unable to get data structure")
	}

	var data = (*netapi32.USER_INFO_1)(unsafe.Pointer(dataPointer))

	if data.Usri1_priv == netapi32.USER_PRIV_ADMIN {
		return true, nil
	} else {
		return false, nil
	}
}

// IsLockedActiveDirectory checks if a user is locked in AD
func IsLockedActiveDirectory(username string, domain string) (bool, error) {
	var dataPointer uintptr
	var dcPointer uintptr
	var servername uintptr

	uPointer, err := syscall.UTF16PtrFromString(username)
	if err != nil {
		return false, fmt.Errorf("Unable to encode username to UTF16")
	}

	if domain != "" {
		dPointer, err := syscall.UTF16PtrFromString(domain)
		if err != nil {
			return false, fmt.Errorf("Unable to encode domain to UTF16")
		}

		_, _, _ = netapi32.NetGetAnyDCName.Call(
			uintptr(0),                        // servername
			uintptr(unsafe.Pointer(dPointer)), // domainame
			uintptr(unsafe.Pointer(&dcPointer)),
		)
		servername = uintptr(dcPointer)
		defer netapi32.NetApiBufferFree.Call(uintptr(unsafe.Pointer(dcPointer)))
	} else {
		servername = uintptr(0)
	}

	_, _, _ = netapi32.NetUserGetInfo.Call(
		servername,                            // servername
		uintptr(unsafe.Pointer(uPointer)),     // username
		uintptr(uint32(2)),                    // level, request USER_INFO_2
		uintptr(unsafe.Pointer(&dataPointer)), // Pointer to struct.
	)
	defer netapi32.NetApiBufferFree.Call(uintptr(unsafe.Pointer(dataPointer)))

	if dataPointer == uintptr(0) {
		return false, fmt.Errorf("Unable to get data structure.")
	}

	data := (*netapi32.USER_INFO_2)(unsafe.Pointer(dataPointer))

	return (data.Usri2_flags & netapi32.USER_UF_LOCKOUT) == netapi32.USER_UF_LOCKOUT, nil
}

// GetList lists information about local user accounts.
func GetList() ([]so.LocalUser, error) {
	var (
		dataPointer  uintptr
		resumeHandle uintptr
		entriesRead  uint32
		entriesTotal uint32
		sizeTest     netapi32.USER_INFO_2
		retVal       = make([]so.LocalUser, 0)
	)

	ret, _, _ := netapi32.NetUserEnum.Call(
		uintptr(0),         // servername
		uintptr(uint32(2)), // level, USER_INFO_2
		uintptr(uint32(netapi32.USER_FILTER_NORMAL_ACCOUNT)), // filter, only "normal" accounts.
		uintptr(unsafe.Pointer(&dataPointer)),                // struct buffer for output data.
		uintptr(uint32(netapi32.USER_MAX_PREFERRED_LENGTH)),  // allow as much memory as required.
		uintptr(unsafe.Pointer(&entriesRead)),
		uintptr(unsafe.Pointer(&entriesTotal)),
		uintptr(unsafe.Pointer(&resumeHandle)),
	)
	if ret != netapi32.NERR_Success {
		return nil, fmt.Errorf("error fetching user entry")
	} else if dataPointer == uintptr(0) {
		return nil, fmt.Errorf("null pointer while fetching entry")
	}

	var iter = dataPointer
	for i := uint32(0); i < entriesRead; i++ {
		var data = (*netapi32.USER_INFO_2)(unsafe.Pointer(iter))

		ud := so.LocalUser{
			Username:         internal.UTF16toString(data.Usri2_name),
			FullName:         internal.UTF16toString(data.Usri2_full_name),
			PasswordAge:      (time.Duration(data.Usri2_password_age) * time.Second),
			LastLogon:        time.Unix(int64(data.Usri2_last_logon), 0),
			BadPasswordCount: data.Usri2_bad_pw_count,
			NumberOfLogons:   data.Usri2_num_logons,
		}

		if (data.Usri2_flags & netapi32.USER_UF_ACCOUNTDISABLE) != netapi32.USER_UF_ACCOUNTDISABLE {
			ud.IsEnabled = true
		}
		if (data.Usri2_flags & netapi32.USER_UF_LOCKOUT) == netapi32.USER_UF_LOCKOUT {
			ud.IsLocked = true
		}
		if (data.Usri2_flags & netapi32.USER_UF_PASSWD_CANT_CHANGE) == netapi32.USER_UF_PASSWD_CANT_CHANGE {
			ud.NoChangePassword = true
		}
		if (data.Usri2_flags & netapi32.USER_UF_DONT_EXPIRE_PASSWD) == netapi32.USER_UF_DONT_EXPIRE_PASSWD {
			ud.PasswordNeverExpires = true
		}
		if data.Usri2_priv == netapi32.USER_PRIV_ADMIN {
			ud.IsAdmin = true
		}

		retVal = append(retVal, ud)

		iter = uintptr(unsafe.Pointer(iter + unsafe.Sizeof(sizeTest)))
	}
	netapi32.NetApiBufferFree.Call(dataPointer)
	return retVal, nil
}

// GrantAdmin adds the user to the "Administrators" group.
func GrantAdmin(username string) (bool, error) {
	return group.AddMember(group.Administrators, username)
}

// RevokeAdmin removes the user from the "Administrators" group.
func RevokeAdmin(username string) (bool, error) {
	return group.RemoveMember(group.Administrators, username)
}

// SetFullname changes the full name attached to the user's account.
func SetFullname(username string, fullname string) (bool, error) {
	var errParam uint32
	uPointer, err := syscall.UTF16PtrFromString(username)
	if err != nil {
		return false, fmt.Errorf("unable to encode username to UTF16")
	}
	fPointer, err := syscall.UTF16PtrFromString(fullname)
	if err != nil {
		return false, fmt.Errorf("unable to encode full name to UTF16")
	}
	ret, _, _ := netapi32.NetUserSetInfo.Call(
		uintptr(0),                        // servername
		uintptr(unsafe.Pointer(uPointer)), // username
		uintptr(uint32(1011)),             // level
		uintptr(unsafe.Pointer(&netapi32.USER_INFO_1011{Usri1011_full_name: fPointer})),
		uintptr(unsafe.Pointer(&errParam)),
	)
	if ret != netapi32.NERR_Success {
		return false, fmt.Errorf("unable to process. %d", ret)
	}
	return true, nil
}

// SetPassword changes the user's password.
func SetPassword(username string, password string) (bool, error) {
	var errParam uint32
	uPointer, err := syscall.UTF16PtrFromString(username)
	if err != nil {
		return false, fmt.Errorf("Unable to encode username to UTF16")
	}
	pPointer, err := syscall.UTF16PtrFromString(password)
	if err != nil {
		return false, fmt.Errorf("Unable to encode username to UTF16")
	}
	ret, _, _ := netapi32.NetUserSetInfo.Call(
		uintptr(0),                        // servername
		uintptr(unsafe.Pointer(uPointer)), // username
		uintptr(uint32(1003)),             // level
		uintptr(unsafe.Pointer(&netapi32.USER_INFO_1003{Usri1003_password: pPointer})),
		uintptr(unsafe.Pointer(&errParam)),
	)
	if ret != netapi32.NERR_Success {
		return false, fmt.Errorf("Unable to process. %d", ret)
	}
	return true, nil
}

// SetProfilePath sets the profile path for the user to path.
func SetProfilePath(username string, path string) (bool, error) {
	var errParam uint32
	uPointer, err := syscall.UTF16PtrFromString(username)
	if err != nil {
		return false, fmt.Errorf("Unable to encode username to UTF16: %v", err)
	}
	pathPointer, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return false, fmt.Errorf("Unable to encode path to UTF16: %v", err)
	}

	ret, _, _ := netapi32.NetUserSetInfo.Call(
		uintptr(0),                        // servername
		uintptr(unsafe.Pointer(uPointer)), // username
		uintptr(uint32(1052)),             // level
		uintptr(unsafe.Pointer(&netapi32.USER_INFO_1052{Useri1052_profile: pathPointer})),
		uintptr(unsafe.Pointer(&errParam)),
	)
	if ret != netapi32.NERR_Success {
		return false, syscall.Errno(ret)
	}
	return true, nil
}

// SetFlagDisabled adds or removes the flag that disables a user's account, preventing
// them from logging in.
// If disable is true, the user's account is disabled.
// If disable is false, the user's account is enabled.
func SetFlagDisabled(username string, disable bool) (bool, error) {
	if disable {
		return addFlags(username, netapi32.USER_UF_ACCOUNTDISABLE)
	} else {
		return delFlags(username, netapi32.USER_UF_ACCOUNTDISABLE)
	}
}

// SetFlagPasswordNeverExpires adds or removes the flag that determines whether the
// user's password expires.
// If noexpire is true, the user's password will not expire.
// If noexpire is false, the user's password will expire according to the system's
// password policy.
func SetFlagPasswordNeverExpires(username string, noexpire bool) (bool, error) {
	if noexpire {
		return addFlags(username, netapi32.USER_UF_DONT_EXPIRE_PASSWD)
	} else {
		return delFlags(username, netapi32.USER_UF_DONT_EXPIRE_PASSWD)
	}
}

// SetFlagDisablePasswordChange adds or removes the flag that determines whether the
// user is allowed to change their own password.
// If disabled is true, the user will be unable to change their own password.
// If disabled is false, the user will be allowed to change their own password.
func SetFlagDisablePasswordChange(username string, disabled bool) (bool, error) {
	if disabled {
		return addFlags(username, netapi32.USER_UF_PASSWD_CANT_CHANGE)
	} else {
		return delFlags(username, netapi32.USER_UF_PASSWD_CANT_CHANGE)
	}
}

func getFlags(username string) (uint32, error) {
	var dataPointer uintptr
	uPointer, err := syscall.UTF16PtrFromString(username)
	if err != nil {
		return 0, fmt.Errorf("unable to encode username to UTF16")
	}
	_, _, _ = netapi32.NetUserGetInfo.Call(
		uintptr(0),                            // servername
		uintptr(unsafe.Pointer(uPointer)),     // username
		uintptr(uint32(1)),                    // level, request USER_INFO_1
		uintptr(unsafe.Pointer(&dataPointer)), // Pointer to struct.
	)
	defer netapi32.NetApiBufferFree.Call(dataPointer)

	if dataPointer == uintptr(0) {
		return 0, fmt.Errorf("unable to get data structure")
	}

	var data = (*netapi32.USER_INFO_1)(unsafe.Pointer(dataPointer))

	fmt.Printf("existing user flags: %d\r\n", data.Usri1_flags)
	return data.Usri1_flags, nil
}

func setFlags(username string, flags uint32) (bool, error) {
	var errParam uint32
	uPointer, err := syscall.UTF16PtrFromString(username)
	if err != nil {
		return false, fmt.Errorf("Unable to encode username to UTF16")
	}
	ret, _, _ := netapi32.NetUserSetInfo.Call(
		uintptr(0),                        // servername
		uintptr(unsafe.Pointer(uPointer)), // username
		uintptr(uint32(1008)),             // level
		uintptr(unsafe.Pointer(&netapi32.USER_INFO_1008{Usri1008_flags: flags})),
		uintptr(unsafe.Pointer(&errParam)),
	)
	if ret != netapi32.NERR_Success {
		return false, fmt.Errorf("Unable to process. %d", ret)
	}
	return true, nil
}

func addFlags(username string, flags uint32) (bool, error) {
	eFlags, err := getFlags(username)
	if err != nil {
		return false, fmt.Errorf("Error while getting existing flags, %s.", err.Error())
	}
	eFlags |= flags // add supplied bits to mask.
	return setFlags(username, eFlags)
}

func delFlags(username string, flags uint32) (bool, error) {
	eFlags, err := getFlags(username)
	if err != nil {
		return false, fmt.Errorf("Error while getting existing flags, %s.", err.Error())
	}
	eFlags &^= flags // clear bits we want to remove.
	return setFlags(username, eFlags)
}
