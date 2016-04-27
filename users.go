package winapi

import (
    "os"
    "fmt"
    "time"
    "syscall"
    "unsafe"
)

var (
    modNetapi32                             = syscall.NewLazyDLL("netapi32.dll")
    usrNetApiBufferFree                     = modNetapi32.NewProc("NetApiBufferFree")
    usrNetUserGetInfo                       = modNetapi32.NewProc("NetUserGetInfo")
    usrNetUserEnum                          = modNetapi32.NewProc("NetUserEnum")
    usrNetUserSetInfo                       = modNetapi32.NewProc("NetUserSetInfo")
    usrNetLocalGroupAddMembers              = modNetapi32.NewProc("NetLocalGroupAddMembers")
    usrNetLocalGroupDelMembers              = modNetapi32.NewProc("NetLocalGroupDelMembers")
)

const (
    NET_API_STATUS_NERR_Success                         = 0
    NET_API_STATUS_NERR_InvalidComputer                 = 2351
    NET_API_STATUS_NERR_NotPrimary                      = 2226
    NET_API_STATUS_NERR_SpeGroupOp                      = 2234
    NET_API_STATUS_NERR_LastAdmin                       = 2452
    NET_API_STATUS_NERR_BadPassword                     = 2203
    NET_API_STATUS_NERR_PasswordTooShort                = 2245
    NET_API_STATUS_NERR_UserNotFound                    = 2221
    NET_API_STATUS_ERROR_ACCESS_DENIED                  = 5
    NET_API_STATUS_ERROR_NOT_ENOUGH_MEMORY              = 8
    NET_API_STATUS_ERROR_INVALID_PARAMETER              = 87
    NET_API_STATUS_ERROR_INVALID_NAME                   = 123
    NET_API_STATUS_ERROR_INVALID_LEVEL                  = 124
    NET_API_STATUS_ERROR_MORE_DATA                      = 234
    NET_API_STATUS_ERROR_SESSION_CREDENTIAL_CONFLICT    = 1219
    NET_API_STATUS_RPC_S_SERVER_UNAVAILABLE             = 2147944122
    NET_API_STATUS_RPC_E_REMOTE_DISABLED                = 2147549468

    USER_PRIV_MASK                                      = 0x3
    USER_PRIV_GUEST                                     = 0
    USER_PRIV_USER                                      = 1
    USER_PRIV_ADMIN                                     = 2

    USER_FILTER_NORMAL_ACCOUNT                          = 0x0002
    USER_MAX_PREFERRED_LENGTH                           = 0xFFFFFFFF

    USER_UF_ACCOUNTDISABLE                              = 2
    USER_UF_LOCKOUT                                     = 16
    USER_UF_PASSWD_CANT_CHANGE                          = 64
    USER_UF_DONT_EXPIRE_PASSWD                          = 65536
)

type USER_INFO_1 struct {
    Usri1_name              *uint16
    Usri1_password          *uint16
    Usri1_password_age      uint32
    Usri1_priv              uint32
    Usri1_home_dir          *uint16
    Usri1_comment           *uint16
    Usri1_flags             uint32
    Usri1_script_path       *uint16
}

type USER_INFO_2 struct {
    Usri2_name              *uint16
    Usri2_password          *uint16
    Usri2_password_age      uint32
    Usri2_priv              uint32
    Usri2_home_dir          *uint16
    Usri2_comment           *uint16
    Usri2_flags             uint32
    Usri2_script_path       *uint16
    Usri2_auth_flags        uint32
    Usri2_full_name         *uint16
    Usri2_usr_comment       *uint16
    Usri2_parms             *uint16
    Usri2_workstations      *uint16
    Usri2_last_logon        uint32
    Usri2_last_logoff       uint32
    Usri2_acct_expires      uint32
    Usri2_max_storage       uint32
    Usri2_units_per_week    uint32
    Usri2_logon_hours       uintptr
    Usri2_bad_pw_count      uint32
    Usri2_num_logons        uint32
    Usri2_logon_server      *uint16
    Usri2_country_code      uint32
    Usri2_code_page         uint32
}

type USER_INFO_1003 struct {
    Usri1003_password       *uint16
}

type USER_INFO_1008 struct {
    Usri1008_flags          uint32
}

type LOCALGROUP_MEMBERS_INFO_3 struct {
    Lgrmi3_domainandname    *uint16
}

type LocalUser struct {
    Username                string
    FullName                string
    IsEnabled               bool
    IsLocked                bool
    IsAdmin                 bool
    PasswordNeverExpires    bool
    NoChangePassword        bool
    PasswordAge             time.Duration
    LastLogon               time.Time
    BadPasswordCount        uint32
    NumberOfLogons          uint32
}

func IsLocalUserAdmin(username string) (bool, error) {
    var dataPointer uintptr
    uPointer, err := syscall.UTF16PtrFromString(username)
    if err != nil {
        return false, fmt.Errorf("Unable to encode username to UTF16")
    }
    _, _, _ = usrNetUserGetInfo.Call(
        uintptr(0), // servername
        uintptr(unsafe.Pointer(uPointer)), // username
        uintptr(uint32(1)), // level, request USER_INFO_1
        uintptr(unsafe.Pointer(&dataPointer)), // Pointer to struct.
    )
    defer usrNetApiBufferFree.Call(uintptr(unsafe.Pointer(dataPointer)))

    if dataPointer == uintptr(0) {
        return false, fmt.Errorf("Unable to get data structure.")
    }

    var data *USER_INFO_1 = (*USER_INFO_1)(unsafe.Pointer(dataPointer))

    if data.Usri1_priv == USER_PRIV_ADMIN {
        return true, nil
    } else {
        return false, nil
    }
}

func ListLocalUsers() ([]LocalUser, error) {
    var (
        dataPointer     uintptr
        resumeHandle    uintptr
        entriesRead     uint32
        entriesTotal    uint32
        sizeTest        USER_INFO_2
        retVal          []LocalUser     = make([]LocalUser, 0)
    )

    ret, _, _ := usrNetUserEnum.Call(
        uintptr(0), // servername
        uintptr(uint32(2)), // level, USER_INFO_2
        uintptr(uint32(USER_FILTER_NORMAL_ACCOUNT)), // filter, only "normal" accounts.
        uintptr(unsafe.Pointer(&dataPointer)), // struct buffer for output data.
        uintptr(uint32(USER_MAX_PREFERRED_LENGTH)), // allow as much memory as required.
        uintptr(unsafe.Pointer(&entriesRead)),
        uintptr(unsafe.Pointer(&entriesTotal)),
        uintptr(unsafe.Pointer(&resumeHandle)),
    )
    if ret != NET_API_STATUS_NERR_Success {
        return nil, fmt.Errorf("Error fetching user entry.")
    } else if ( dataPointer == uintptr(0) ){
        return nil, fmt.Errorf("Null pointer while fetching entry.")
    }

    var iter uintptr = dataPointer
    for i := uint32(0); i < entriesRead; i++ {
        var data *USER_INFO_2 = (*USER_INFO_2)(unsafe.Pointer(iter))

        ud := LocalUser{
            Username:           UTF16toString(data.Usri2_name),
            FullName:           UTF16toString(data.Usri2_full_name),
            PasswordAge:        (time.Duration(data.Usri2_password_age) * time.Second),
            LastLogon:          time.Unix(int64(data.Usri2_last_logon), 0),
            BadPasswordCount:   data.Usri2_bad_pw_count,
            NumberOfLogons:     data.Usri2_num_logons,
        }

        if (data.Usri2_flags & USER_UF_ACCOUNTDISABLE) != USER_UF_ACCOUNTDISABLE {
            ud.IsEnabled = true
        }
        if (data.Usri2_flags & USER_UF_LOCKOUT) == USER_UF_LOCKOUT {
            ud.IsLocked = true
        }
        if (data.Usri2_flags & USER_UF_PASSWD_CANT_CHANGE) == USER_UF_PASSWD_CANT_CHANGE {
            ud.NoChangePassword = true
        }
        if (data.Usri2_flags & USER_UF_DONT_EXPIRE_PASSWD) == USER_UF_DONT_EXPIRE_PASSWD {
            ud.PasswordNeverExpires = true
        }
        if data.Usri2_priv == USER_PRIV_ADMIN {
            ud.IsAdmin = true
        }

        retVal = append(retVal, ud)

        iter = uintptr(unsafe.Pointer(iter + unsafe.Sizeof(sizeTest)))
    }
    _, _, _ = usrNetApiBufferFree.Call(uintptr(unsafe.Pointer(dataPointer)))
    return retVal, nil
}

func SetAdmin(username string) (bool, error) {
    hn, _ := os.Hostname()
    uPointer, err := syscall.UTF16PtrFromString(hn + `\` + username)
    if err != nil {
        return false, fmt.Errorf("Unable to encode username to UTF16")
    }
    gPointer, err := syscall.UTF16PtrFromString("Administrators")
    if err != nil {
        return false, fmt.Errorf("Unable to encode group name to UTF16")
    }
    var uArray []LOCALGROUP_MEMBERS_INFO_3 = make([]LOCALGROUP_MEMBERS_INFO_3, 1)
    uArray[0] = LOCALGROUP_MEMBERS_INFO_3{
        Lgrmi3_domainandname: uPointer,
    }
    ret, _, _ := usrNetLocalGroupAddMembers.Call(
        uintptr(0), // servername
        uintptr(unsafe.Pointer(gPointer)), // group name
        uintptr(uint32(3)), // level
        uintptr(unsafe.Pointer(&uArray[0])), // user array.
        uintptr(uint32(len(uArray))),
    )
    if ret != NET_API_STATUS_NERR_Success {
        return false, fmt.Errorf("Unable to process. %d", ret)
    }
    return true, nil
}

func RevokeAdmin(username string) (bool, error) {
    hn, _ := os.Hostname()
    uPointer, err := syscall.UTF16PtrFromString(hn + `\` + username)
    if err != nil {
        return false, fmt.Errorf("Unable to encode username to UTF16")
    }
    gPointer, err := syscall.UTF16PtrFromString("Administrators")
    if err != nil {
        return false, fmt.Errorf("Unable to encode group name to UTF16")
    }
    var uArray []LOCALGROUP_MEMBERS_INFO_3 = make([]LOCALGROUP_MEMBERS_INFO_3, 1)
    uArray[0] = LOCALGROUP_MEMBERS_INFO_3{
        Lgrmi3_domainandname: uPointer,
    }
    ret, _, _ := usrNetLocalGroupDelMembers.Call(
        uintptr(0), // servername
        uintptr(unsafe.Pointer(gPointer)), // group name
        uintptr(uint32(3)), // level
        uintptr(unsafe.Pointer(&uArray[0])), // user array.
        uintptr(uint32(len(uArray))),
    )
    if ret != NET_API_STATUS_NERR_Success {
        return false, fmt.Errorf("Unable to process. %d", ret)
    }
    return true, nil
}

func ChangePassword(username string, password string) (bool, error) {
    var errParam uint32
    uPointer, err := syscall.UTF16PtrFromString(username)
    if err != nil {
        return false, fmt.Errorf("Unable to encode username to UTF16")
    }
    pPointer, err := syscall.UTF16PtrFromString(password)
    if err != nil {
        return false, fmt.Errorf("Unable to encode username to UTF16")
    }
    ret, _, _ := usrNetUserSetInfo.Call(
        uintptr(0), // servername
        uintptr(unsafe.Pointer(uPointer)), // username
        uintptr(uint32(1003)), // level
        uintptr(unsafe.Pointer(&USER_INFO_1003{ Usri1003_password: pPointer })),
        uintptr(unsafe.Pointer(&errParam)),
    )
    if ret != NET_API_STATUS_NERR_Success {
        return false, fmt.Errorf("Unable to process. %d", ret)
    }
    return true, nil
}

func UTF16toString(p *uint16) string {
	return syscall.UTF16ToString((*[4096]uint16)(unsafe.Pointer(p))[:])
}
