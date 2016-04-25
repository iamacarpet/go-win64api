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
)

// Some constants from the Windows API
const (
    ERROR_NO_MORE_FILES                 = 0x12
    PROCESS_QUERY_LIMITED_INFORMATION   = 0x1000
    MAX_PATH                            = 260
    MAX_FULL_PATH                       = 4096
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

// WindowsProcess is an implementation of Process for Windows.
type Process struct {
    pid                 int             `json:"pid"`
    ppid                int             `json:"parentpid"`
    exe                 string          `json:"exeName"`
    fullpath            string          `json:"fullPath"`
}

func (p *Process) Pid() int {
    return p.pid
}

func (p *Process) PPid() int {
    return p.ppid
}

func (p *Process) Executable() string {
    return p.exe
}

func (p *Process) FullPath() string {
    return p.fullpath
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
        pid:        int(e.ProcessID),
        ppid:       int(e.ParentProcessID),
        exe:        syscall.UTF16ToString(e.ExeFile[:end]),
        fullpath:   path,
    }
}

func ProcessList() ([]*Process, error) {
    handle, _, _ := procCreateToolhelp32Snapshot.Call(0x00000002, 0)
    if handle < 0 {
        return nil, syscall.GetLastError()
    }
    defer procCloseHandle.Call(handle)

    var entry PROCESSENTRY32
    entry.Size = uint32(unsafe.Sizeof(entry))
    ret, _, _ := procProcess32First.Call(handle, uintptr(unsafe.Pointer(&entry)))
    if ret == 0 {
        return nil, fmt.Errorf("Error retrieving process info.")
    }

    results := make([]*Process, 0)
    for {
        path, _ := getProcessFullPath(entry.ProcessID)
        results = append(results, newProcessData(&entry, path))

        ret, _, _ := procProcess32Next.Call(handle, uintptr(unsafe.Pointer(&entry)))
        if ret == 0 {
            break
        }
    }

    return results, nil
}

func getProcessFullPath(pid uint32) (string, error) {
    handle, _, _ := procOpenProcess.Call(uintptr(uint32(PROCESS_QUERY_LIMITED_INFORMATION)), uintptr(0), uintptr(pid))
    if handle < 0 {
        return "", syscall.GetLastError()
    }
    defer procCloseHandle.Call(handle)

    var pathName [MAX_FULL_PATH]uint16
    pathLength := uint32(MAX_FULL_PATH)
    ret, _, _ := procQueryFullProcessImageName.Call(handle, uintptr(0), uintptr(unsafe.Pointer(&pathName)), uintptr(unsafe.Pointer(&pathLength)))

    if ret > 0 {
        return syscall.UTF16ToString(pathName[:pathLength]), nil
    } else {
        return "", fmt.Errorf("Unable to get full path!")
    }
}
