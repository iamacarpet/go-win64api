package winapi

import (
    "fmt"
    "syscall"
    "unsafe"
)

// Windows API functions
var (
    modKernel32                         = syscall.NewLazyDLL("kernel32.dll")
    procCloseHandle                     = modKernel32.NewProc("CloseHandle")
    procOpenProcess                     = modKernel32.NewProc("OpenProcess")
    procCreateToolhelp32Snapshot        = modKernel32.NewProc("CreateToolhelp32Snapshot")
    procProcess32First                  = modKernel32.NewProc("Process32FirstW")
    procProcess32Next                   = modKernel32.NewProc("Process32NextW")
    procQueryFullProcessImageName       = modKernel32.NewProc("QueryFullProcessImageNameW")
    procGetCurrentProcess               = modKernel32.NewProc("GetCurrentProcess")
    procGetLastError                    = modKernel32.NewProc("GetLastError")

    modAdvapi32                         = syscall.NewLazyDLL("advapi32.dll")
    procOpenProcessToken                = modAdvapi32.NewProc("OpenProcessToken")
    procLookupPrivilegeValue            = modAdvapi32.NewProc("LookupPrivilegeValueW")
    procAdjustTokenPrivileges           = modAdvapi32.NewProc("AdjustTokenPrivileges")
    procGetTokenInformation             = modAdvapi32.NewProc("GetTokenInformation")
    procLookupAccountSid                = modAdvapi32.NewProc("LookupAccountSidW")
)

// Some constants from the Windows API
const (
    ERROR_NO_MORE_FILES                 = 0x12
    PROCESS_QUERY_INFORMATION           = 0x0400
    PROCESS_QUERY_LIMITED_INFORMATION   = 0x1000
    MAX_PATH                            = 260
    MAX_FULL_PATH                       = 4096

    PROC_TOKEN_QUERY                    = 0x0008
    PROC_TOKEN_ADJUST_PRIVILEGES        = 0x0020

    PROC_SE_PRIVILEGE_ENABLED           = 0x00000002

    PROC_SE_DEBUG_NAME                  = "SeDebugPrivilege"
)

// PROCESSENTRY32 is the Windows API structure that contains a process's
// information.
type PROCESSENTRY32 struct {
    Size                uint32
    CntUsage            uint32
    ProcessID           uint32
    DefaultHeapID       uintptr
    ModuleID            uint32
    CntThreads          uint32
    ParentProcessID     uint32
    PriorityClassBase   int32
    Flags               uint32
    ExeFile             [MAX_PATH]uint16
}

type TOKEN_PRIVILEGES struct {
    PrivilegeCount      uint32
    Privileges          [1]LUID_AND_ATTRIBUTES
}

type LUID_AND_ATTRIBUTES struct {
    LUID                LUID
    Attributes          uint32
}

type TOKEN_USER struct {
    User                SID_AND_ATTRIBUTES
}

type SID_AND_ATTRIBUTES struct {
    Sid                 uintptr
    Attributes          uint32
}

type TOKEN_STATISTICS struct {
    TokenId             LUID
    AuthenticationId    LUID
    ExpirationTime      uint64
    TokenType           uint32
    ImpersonationLevel  uint32
    DynamicCharged      uint32
    DynamicAvailable    uint32
    GroupCount          uint32
    PrivilegeCount      uint32
    ModifiedId          LUID
}

// WindowsProcess is an implementation of Process for Windows.
type Process struct {
    Pid                 int             `json:"pid"`
    Ppid                int             `json:"parentpid"`
    Executable          string          `json:"exeName"`
    Fullpath            string          `json:"fullPath"`
    Username            string          `json:"user"`
}

func newProcessData(e *PROCESSENTRY32, path string) *Process {
    // Find when the string ends for decoding
    end := 0
    for {
        if e.ExeFile[end] == 0 {
            break
        }
        end++
    }

    return &Process{
        Pid:        int(e.ProcessID),
        Ppid:       int(e.ParentProcessID),
        Executable: syscall.UTF16ToString(e.ExeFile[:end]),
        Fullpath:   path,
    }
}

func ProcessList() ([]*Process, map[uint32]LUID, error) {
    err := procAssignCorrectPrivs()
    if err != nil {
        return nil, nil, fmt.Errorf("Error assigning privs... %s", err.Error())
    }

    handle, _, _ := procCreateToolhelp32Snapshot.Call(0x00000002, 0)
    if handle < 0 {
        return nil, nil, syscall.GetLastError()
    }
    defer procCloseHandle.Call(handle)

    pMap := make(map[uint32]LUID)

    var entry PROCESSENTRY32
    entry.Size = uint32(unsafe.Sizeof(entry))
    ret, _, _ := procProcess32First.Call(handle, uintptr(unsafe.Pointer(&entry)))
    if ret == 0 {
        return nil, nil, fmt.Errorf("Error retrieving process info.")
    }

    results := make([]*Process, 0)
    for {
        path, ll, _ := getProcessFullPathAndUsername(entry.ProcessID)
        results = append(results, newProcessData(&entry, path))
        pMap[entry.ProcessID] = ll

        ret, _, _ := procProcess32Next.Call(handle, uintptr(unsafe.Pointer(&entry)))
        if ret == 0 {
            break
        }
    }

    return results, pMap, nil
}

func procAssignCorrectPrivs() (error) {
    handle, _, _ := procGetCurrentProcess.Call()
    if handle == uintptr(0) {
        return fmt.Errorf("Unable to get current process handle.")
    }
    defer procCloseHandle.Call(handle)

    var tHandle uintptr
    opRes, _, _ := procOpenProcessToken.Call(
        uintptr(handle),
        uintptr(uint32(PROC_TOKEN_ADJUST_PRIVILEGES)),
        uintptr(unsafe.Pointer(&tHandle)),
    )
    if opRes != 1 {
        return fmt.Errorf("Unable to open current process token.")
    }
    defer procCloseHandle.Call(tHandle)

    nPointer, err := syscall.UTF16PtrFromString(PROC_SE_DEBUG_NAME)
    if err != nil {
        return fmt.Errorf("Unable to encode SE_DEBUG_NAME to UTF16")
    }
    var pValue LUID
    lpRes, _, _ := procLookupPrivilegeValue.Call(
        uintptr(0),
        uintptr(unsafe.Pointer(nPointer)),
        uintptr(unsafe.Pointer(&pValue)),
    )
    if lpRes != 1 {
        return fmt.Errorf("Unable to lookup priv value.")
    }

    iVal := TOKEN_PRIVILEGES{
        PrivilegeCount:     1,
    }
    iVal.Privileges[0] = LUID_AND_ATTRIBUTES{
        LUID:           pValue,
        Attributes:     PROC_SE_PRIVILEGE_ENABLED,
    }
    ajRes, _, _ := procAdjustTokenPrivileges.Call(
        uintptr(tHandle),
        uintptr(uint32(0)),
        uintptr(unsafe.Pointer(&iVal)),
        uintptr(uint32(0)),
        uintptr(0),
        uintptr(0),
    )
    if ajRes != 1 {
        return fmt.Errorf("Error while adjusting process token.")
    }
    return nil
}

func getProcessFullPathAndUsername(pid uint32) (string, LUID, error) {
    var fullpath string

    handle, _, _ := procOpenProcess.Call(uintptr(uint32(PROCESS_QUERY_INFORMATION)), uintptr(0), uintptr(pid))
    if handle < 0 {
        return "", LUID{}, syscall.GetLastError()
    }
    defer procCloseHandle.Call(handle)

    var pathName [MAX_FULL_PATH]uint16
    pathLength := uint32(MAX_FULL_PATH)
    ret, _, _ := procQueryFullProcessImageName.Call(handle, uintptr(0), uintptr(unsafe.Pointer(&pathName)), uintptr(unsafe.Pointer(&pathLength)))

    if ret > 0 {
        fullpath = syscall.UTF16ToString(pathName[:pathLength])
    }

    var tHandle uintptr
    opRes, _, _ := procOpenProcessToken.Call(
        uintptr(handle),
        uintptr(uint32(PROC_TOKEN_QUERY)),
        uintptr(unsafe.Pointer(&tHandle)),
    )
    if opRes != 1 {
        return fullpath, LUID{}, fmt.Errorf("Unable to open process token.")
    }
    defer procCloseHandle.Call(tHandle)

    var sData   TOKEN_STATISTICS
    var sLength uint32
    tsRes, _, _ := procGetTokenInformation.Call(
        uintptr(tHandle),
        uintptr(uint32(10)), // TOKEN_STATISTICS
        uintptr(unsafe.Pointer(&sData)),
        uintptr(uint32(unsafe.Sizeof(sData))),
        uintptr(unsafe.Pointer(&sLength)),
    )
    if tsRes != 1 {
        return fullpath, LUID{}, fmt.Errorf("Error fetching token information (LUID).")
    }

    return fullpath, sData.AuthenticationId, nil
}
