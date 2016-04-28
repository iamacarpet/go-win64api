package winapi

import (
    "os"
    "fmt"
    "sort"
    "strings"
    "syscall"
    "unsafe"
    "reflect"

    so "windows-api-test/winapi/shared"
)

var (
    modSecur32                          = syscall.NewLazyDLL("secur32.dll")
    sessLsaFreeReturnBuffer             = modSecur32.NewProc("LsaFreeReturnBuffer")
    sessLsaEnumerateLogonSessions       = modSecur32.NewProc("LsaEnumerateLogonSessions")
    sessLsaGetLogonSessionData          = modSecur32.NewProc("LsaGetLogonSessionData")
)

const (
    SESS_INTERACTIVE_LOGON              = 2
)

type LUID struct {
    LowPart     uint32
    HighPart    int32
}

type SECURITY_LOGON_SESSION_DATA struct {
    Size                    uint32
    LogonId                 LUID
    UserName                LSA_UNICODE_STRING
    LogonDomain             LSA_UNICODE_STRING
    AuthenticationPackage   LSA_UNICODE_STRING
    LogonType               uint32
    Session                 uint32
    Sid                     uintptr
    LogonTime               uint64
    LogonServer             LSA_UNICODE_STRING
    DnsDomainName           LSA_UNICODE_STRING
    Upn                     LSA_UNICODE_STRING
}

type LSA_UNICODE_STRING struct {
    Length                  uint16
    MaximumLength           uint16
    buffer                  uintptr
}

func ListLoggedInUsers() ([]so.SessionDetails, error) {
    var (
        logonSessionCount       uint64
        loginSessionList        uintptr
        sizeTest                LUID
        uList                   []string            = make([]string, 0)
        uSessList               []so.SessionDetails    = make([]so.SessionDetails, 0)
        PidLUIDList             map[uint32]LUID
    )
    PidLUIDList, err := ProcessLUIDList()
    if err != nil {
        return nil, fmt.Errorf("Error getting process list, %s.", err.Error())
    }

    _, _, _ = sessLsaEnumerateLogonSessions.Call(
        uintptr(unsafe.Pointer(&logonSessionCount)),
        uintptr(unsafe.Pointer(&loginSessionList)),
    )
    defer sessLsaFreeReturnBuffer.Call(uintptr(unsafe.Pointer(&loginSessionList)))

    var iter uintptr = uintptr(unsafe.Pointer(loginSessionList))

    for i := uint64(0); i < logonSessionCount; i++ {
        var sessionData uintptr
        _, _, _ = sessLsaGetLogonSessionData.Call(uintptr(iter), uintptr(unsafe.Pointer(&sessionData)))
        if sessionData != uintptr(0){
            var data *SECURITY_LOGON_SESSION_DATA = (*SECURITY_LOGON_SESSION_DATA)(unsafe.Pointer(sessionData))

            if data.Sid != uintptr(0) {
                if data.LogonType == SESS_INTERACTIVE_LOGON {
                    if LsatoString(data.LogonDomain) != "Window Manager" {
                        sUser := fmt.Sprintf("%s\\%s", strings.ToUpper(LsatoString(data.LogonDomain)), strings.ToLower(LsatoString(data.UserName)))
                        sort.Strings(uList)
                        i := sort.Search(len(uList), func(i int) bool { return uList[i] >= sUser })
                        if !(i < len(uList) && uList[i] == sUser) {
                            if luidinmap(&data.LogonId, &PidLUIDList) {
                                uList = append(uList, sUser)
                                ud := so.SessionDetails{
                                    Username: strings.ToLower(LsatoString(data.UserName)),
                                    Domain: strings.ToUpper(LsatoString(data.LogonDomain)),
                                }
                                hn, _ := os.Hostname()
                                if strings.ToUpper(ud.Domain) == strings.ToUpper(hn) {
                                    ud.LocalUser = true
                                    if isAdmin, _ := IsLocalUserAdmin(ud.Username); isAdmin {
                                        ud.LocalAdmin = true
                                    }
                                }
                                uSessList = append(uSessList, ud)
                            }
                        }
                    }
                }
            }
        }

        iter = uintptr(unsafe.Pointer(iter + unsafe.Sizeof(sizeTest)))
        _, _, _ = sessLsaFreeReturnBuffer.Call(uintptr(unsafe.Pointer(sessionData)))
    }

    return uSessList, nil
}

func sessUserLUIDs() (map[LUID]string, error) {
    var (
        logonSessionCount       uint64
        loginSessionList        uintptr
        sizeTest                LUID
        uList                   map[LUID]string     = make(map[LUID]string)
    )

    _, _, _ = sessLsaEnumerateLogonSessions.Call(
        uintptr(unsafe.Pointer(&logonSessionCount)),
        uintptr(unsafe.Pointer(&loginSessionList)),
    )
    defer sessLsaFreeReturnBuffer.Call(uintptr(unsafe.Pointer(&loginSessionList)))

    var iter uintptr = uintptr(unsafe.Pointer(loginSessionList))

    for i := uint64(0); i < logonSessionCount; i++ {
        var sessionData uintptr
        _, _, _ = sessLsaGetLogonSessionData.Call(uintptr(iter), uintptr(unsafe.Pointer(&sessionData)))
        if sessionData != uintptr(0){
            var data *SECURITY_LOGON_SESSION_DATA = (*SECURITY_LOGON_SESSION_DATA)(unsafe.Pointer(sessionData))

            if data.Sid != uintptr(0) {
                uList[data.LogonId] = fmt.Sprintf("%s\\%s", strings.ToUpper(LsatoString(data.LogonDomain)), strings.ToLower(LsatoString(data.UserName)))
            }
        }

        iter = uintptr(unsafe.Pointer(iter + unsafe.Sizeof(sizeTest)))
        _, _, _ = sessLsaFreeReturnBuffer.Call(uintptr(unsafe.Pointer(sessionData)))
    }

    return uList, nil
}

func luidinmap(needle *LUID, haystack *map[uint32]LUID) (bool) {
    for _, l := range *haystack {
        if reflect.DeepEqual(l, *needle) {
            return true
        }
    }
    return false
}

func LsatoString(p LSA_UNICODE_STRING) string {
    return syscall.UTF16ToString((*[4096]uint16)(unsafe.Pointer(p.buffer))[:p.Length])
}
