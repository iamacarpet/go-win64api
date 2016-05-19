package shared

import (
    "time"
)

type Hardware struct {
    HardwareUUID        string
    Manufacturer        string
    Model               string
    ServiceTag          string
    BIOSVersion         string
    BIOSManufacturer    string
    BIOSReleaseDate     time.Time
    CPU                 []CPU
    Memory              []MemoryDIMM
}

type CPU struct {
    FriendlyName        string
    NumberOfCores       uint8
    NumberOfLogical     uint8
}

type MemoryDIMM struct {
    MType               string
    Size                uint64
    Speed               uint16
}

type OperatingSystem struct {
    FriendlyName        string
    Version             string
    Architecture        string
    LanguageCode        uint16
}

type Memory struct {
    TotalRAM                uint64
    UsableRAM               uint64
    FreeRAM                 uint64
    TotalPageFile           uint64
    FreePageFile            uint64
    SystemManagedPageFile   bool
}

type Disk struct {
    DriveName           string
    TotalSize           uint64
    Available           uint64
    FileSystem          string
}

type Network struct {
    Name                string
    MACAddress          string
    IPAddressCIDR       []string
    DHCPEnabled         bool
}
