package winapi

import (
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	modOffreg            = syscall.NewLazyDLL("Offreg.dll")
	procOROpenHive       = modOffreg.NewProc("OROpenHive")
	procORSaveHive       = modOffreg.NewProc("ORSaveHive")
	procORCloseHive      = modOffreg.NewProc("ORCloseHive")
	procORGetKeySecurity = modOffreg.NewProc("ORGetKeySecurity")
	procORSetKeySecurity = modOffreg.NewProc("ORSetKeySecurity")
)

// OROpenHive opens a registry hive outside the active system
func OROpenHive(hivePath string) (syscall.Handle, error) {
	// Convert path to ptr
	hivePathPtr, err := syscall.UTF16PtrFromString(hivePath)
	if err != nil {
		return syscall.Handle(0), err
	}
	// Declare key
	var key syscall.Handle

	// Open Hive
	r1, _, err := procOROpenHive.Call(
		uintptr(unsafe.Pointer(hivePathPtr)),
		uintptr(unsafe.Pointer(&key)),
	)
	if r1 != 0 {
		return syscall.Handle(0), err
	}
	return key, nil
}

// ORSaveHive saves changes to the offline registry hive
func ORSaveHive(key syscall.Handle, hivePath string) error {
	// Convert path to ptr
	hivePathPtr, err := syscall.UTF16PtrFromString(hivePath)
	if err != nil {
		return err
	}

	// Save Hive
	r1, _, err := procORSaveHive.Call(
		uintptr(key),
		uintptr(unsafe.Pointer(hivePathPtr)),
		uintptr(10),
		uintptr(0),
	)
	if r1 != 0 {
		return err
	}
	return nil
}

// ORCloseHive closes offline registry hive
func ORCloseHive(key syscall.Handle) error {
	// Close Hive
	r1, _, err := procORCloseHive.Call(
		uintptr(key),
	)
	if r1 != 0 {
		return err
	}
	return nil
}

// ORGetKeySecurityBuffer Gets
func ORGetKeySecurityBuffer(key syscall.Handle, secInfo windows.SECURITY_INFORMATION) ([]uint16, error) {
	// Initialize size and call for the first time
	var bufferSize uint32
	r1, _, err := procORGetKeySecurity.Call(
		uintptr(key),
		uintptr(secInfo),
		uintptr(0),
		uintptr(unsafe.Pointer(&bufferSize)),
	)

	// Check bufferSize
	if bufferSize == 0 {
		return nil, err
	}
	// Get security description
	secDescriptor := make([]uint16, bufferSize)
	r1, _, err = procORGetKeySecurity.Call(
		uintptr(key),
		uintptr(secInfo),
		uintptr(unsafe.Pointer(&secDescriptor[0])),
		uintptr(unsafe.Pointer(&bufferSize)),
	)
	if r1 != 0 {
		return nil, err
	}
	return secDescriptor, nil
}

// ORGetKeySecurityStructure Gets
func ORGetKeySecurityStructure(key syscall.Handle, secInfo windows.SECURITY_INFORMATION) (windows.SECURITY_DESCRIPTOR, error) {
	// Initialize size and call for the first time
	var bufferSize uint32
	r1, _, err := procORGetKeySecurity.Call(
		uintptr(key),
		uintptr(secInfo),
		uintptr(0),
		uintptr(unsafe.Pointer(&bufferSize)),
	)

	// Check bufferSize
	if bufferSize == 0 {
		return windows.SECURITY_DESCRIPTOR{}, err
	}
	// Get security description
	var secDescriptor windows.SECURITY_DESCRIPTOR
	r1, _, err = procORGetKeySecurity.Call(
		uintptr(key),
		uintptr(secInfo),
		uintptr(unsafe.Pointer(&secDescriptor)),
		uintptr(unsafe.Pointer(&bufferSize)),
	)
	if r1 != 0 {
		return windows.SECURITY_DESCRIPTOR{}, err
	}
	return secDescriptor, nil
}

// ORSetKeySecurity Gets
func ORSetKeySecurity(key syscall.Handle, secInfo windows.SECURITY_INFORMATION, secDescriptor []uint16) error {
	// Set security description
	r1, _, err := procORSetKeySecurity.Call(
		uintptr(key),
		uintptr(secInfo),
		uintptr(unsafe.Pointer(&secDescriptor[0])),
	)
	if r1 != 0 {
		return err
	}
	return nil
}

// ORAddFullPermissions adds full control to a user over an offline registry hive.
func ORAddFullPermissions(srcHivePath string, dstHivePath string, username string) error {
	// Open Hive
	key, err := OROpenHive(srcHivePath)
	if err != nil {
		return err
	}
	// Get Security Descriptor Self-Relative
	SRsecDes, err := ORGetKeySecurityBuffer(key, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return err
	}
	// Get Security Descriptor Absolute
	AsecDes, err := MakeAbsoluteSD(SRsecDes)
	if err != nil {
		return err
	}
	// Get DACL
	dacl, present, defaulted, err := GetSecurityDescriptorDACL(SRsecDes)
	if err != nil {
		return err
	}
	// Add ACE
	newACL, err := ACLAddControl([]string{username}, dacl, windows.KEY_ALL_ACCESS, windows.SET_ACCESS)
	if err != nil {
		return err
	}
	// Save DACL
	err = SetSecurityDescriptorDACL(AsecDes, newACL, present, defaulted)
	if err != nil {
		return err
	}
	// Convert to Self Relative
	SRsecDes, err = MakeSelfRelativeSD(AsecDes)
	if err != nil {
		return err
	}
	// Set new Security Descriptor
	err = ORSetKeySecurity(key, windows.DACL_SECURITY_INFORMATION, SRsecDes)
	if err != nil {
		return err
	}
	// Save Hive
	err = ORSaveHive(key, dstHivePath)
	if err != nil {
		return err
	}
	// Close Hive
	err = ORCloseHive(key)
	if err != nil {
		return err
	}
	return nil
}
