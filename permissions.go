package winapi

import (
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	procGetFileSecurity           = modAdvapi32.NewProc("GetFileSecurityW")
	procSetFileSecurity           = modAdvapi32.NewProc("SetFileSecurityW")
	procAddAce                    = modAdvapi32.NewProc("AddAce")
	procSetEntriesInACL           = modAdvapi32.NewProc("SetEntriesInAclW")
	procGetSecurityDescriptorDACL = modAdvapi32.NewProc("GetSecurityDescriptorDacl")
	procSetSecurityDescriptorDACL = modAdvapi32.NewProc("SetSecurityDescriptorDacl")
	procGetExplicitEntriesFromACL = modAdvapi32.NewProc("GetExplicitEntriesFromAclW")
	procIsValidSecurityDescriptor = modAdvapi32.NewProc("IsValidSecurityDescriptor")
	procMakeAbsoluteSD            = modAdvapi32.NewProc("MakeAbsoluteSD")
	procMakeSelfRelativeSD        = modAdvapi32.NewProc("MakeSelfRelativeSD")
)

// GetFileSecurityDescriptor returns a buffer with the file sec Descriptor
func GetFileSecurityDescriptor(path string, secInfo windows.SECURITY_INFORMATION) ([]uint16, error) {
	//Convert path
	pathPtr, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	//Initialize size and call for the first time
	var bufferSize uint32
	r1, _, err := procGetFileSecurity.Call(
		uintptr(unsafe.Pointer(pathPtr)),
		uintptr(secInfo),
		uintptr(0),
		uintptr(0),
		uintptr(unsafe.Pointer(&bufferSize)),
	)

	if bufferSize == 0 {
		return nil, err
	}

	secDescriptor := make([]uint16, bufferSize)
	r1, _, err = procGetFileSecurity.Call(
		uintptr(unsafe.Pointer(&path)),
		uintptr(secInfo),
		uintptr(unsafe.Pointer(&[0]secDescriptor)),
		uintptr(bufferSize),
		uintptr(unsafe.Pointer(&bufferSize)),
	)
	if r1 == 0 {
		return nil, err
	}
	return secDescriptor, nil
}

// IsValidSecDescriptor returns true is the secDescriptor is valid
func IsValidSecDescriptor(secDescriptor []uint16) (bool, error) {
	r1, _, err := procIsValidSecurityDescriptor.Call(
		uintptr(unsafe.Pointer(&secDescriptor[0])),
	)
	if r1 == 0 {
		return false, err
	}
	return true, nil
}

// GetExplicitEntriesFromACL gets a list of explicit entries from an ACL
func GetExplicitEntriesFromACL(acl *windows.ACL) (*[]windows.EXPLICIT_ACCESS, error) {
	var explicitEntries *[]windows.EXPLICIT_ACCESS
	var explicitEntriesSize uint64
	// Get dacl
	r1, _, err := procGetExplicitEntriesFromACL.Call(
		uintptr(unsafe.Pointer(acl)),
		uintptr(unsafe.Pointer(&explicitEntriesSize)),
		uintptr(unsafe.Pointer(&explicitEntries)),
	)
	if r1 != 0 {
		return explicitEntries, err
	}
	return explicitEntries, nil
}

// GetSecurityDescriptorDACL gets an DACL from a security descriptor
func GetSecurityDescriptorDACL(pSecDescriptor []uint16) (*windows.ACL, bool, bool, error) {
	var present bool
	var acl *windows.ACL
	var defaulted bool
	// Get dacl
	r1, _, err := procGetSecurityDescriptorDACL.Call(
		uintptr(unsafe.Pointer(&pSecDescriptor[0])),
		uintptr(unsafe.Pointer(&present)),
		uintptr(unsafe.Pointer(&acl)),
		uintptr(unsafe.Pointer(&defaulted)),
	)
	if r1 == 0 && !present {
		return acl, false, false, err
	}
	return acl, present, defaulted, nil
}

// SetSecurityDescriptorDACL sets an DACL for a security descriptor
func SetSecurityDescriptorDACL(pSecDescriptor []uint16, acl *windows.ACL, present bool, defaulted bool) error {
	var presentInt int
	var defaultedInt int
	// Set booleans
	if present {
		presentInt = 1
	}
	if defaulted {
		defaultedInt = 1
	}
	// Set dacl
	r1, _, err := procSetSecurityDescriptorDACL.Call(
		uintptr(unsafe.Pointer(&pSecDescriptor[0])),
		uintptr(presentInt),
		uintptr(unsafe.Pointer(acl)),
		uintptr(defaultedInt),
	)
	if r1 == 0 {
		return err
	}
	return nil
}

// ACLAddFullControl adds full controll permissions for the given user in an ACL
func ACLAddFullControl(username string, acl *windows.ACL) (*windows.ACL, error) {
	// Get user SID
	rawSid, err := GetRawSidForAccountName(username)
	if err != nil {
		return nil, err
	}
	// Convert Sid to string
	strSid, err := ConvertRawSidToStringSid(rawSid)
	if err != nil {
		return nil, err
	}
	// Get SID from string sid
	sid, err := windows.StringToSid(strSid)
	if err != nil {
		return nil, err
	}
	// Create nnew explicit access structure
	newACEs := []windows.EXPLICIT_ACCESS{
		{
			AccessPermissions: windows.KEY_ALL_ACCESS,
			AccessMode:        windows.SET_ACCESS,
			Inheritance:       windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT,
			Trustee: windows.TRUSTEE{
				MultipleTrustee:          nil,
				MultipleTrusteeOperation: windows.NO_MULTIPLE_TRUSTEE,
				TrusteeForm:              windows.TRUSTEE_IS_SID,
				TrusteeType:              windows.TRUSTEE_IS_USER,
				TrusteeValue:             windows.TrusteeValueFromSID(sid),
			},
		},
	}
	// Explicit entries size
	var newACEsSize uint32 = uint32(len(newACEs))
	// Create new ACL
	var newACL *windows.ACL
	// Get new ACL
	r1, _, err := procSetEntriesInACL.Call(
		uintptr(newACEsSize),
		uintptr(unsafe.Pointer(&newACEs[0])),
		uintptr(unsafe.Pointer(acl)),
		uintptr(unsafe.Pointer(&newACL)),
	)
	if r1 != 0 {
		err = windows.GetLastError()
		return nil, err
	}
	return newACL, nil
}

// MakeAbsoluteSD makes an absolute security descriptor out of a self-relative
func MakeAbsoluteSD(selfRelative []uint16) ([]uint16, error) {
	var AsecDesSize uint32
	var AdaclSize uint32
	var AsaclSize uint32
	var AownerSize uint32
	var AprimaryGroupSize uint32
	// Get sizes
	r1, _, err := procMakeAbsoluteSD.Call(
		uintptr(unsafe.Pointer(&selfRelative[0])),
		uintptr(0),
		uintptr(unsafe.Pointer(&AsecDesSize)),
		uintptr(0),
		uintptr(unsafe.Pointer(&AdaclSize)),
		uintptr(0),
		uintptr(unsafe.Pointer(&AsaclSize)),
		uintptr(0),
		uintptr(unsafe.Pointer(&AownerSize)),
		uintptr(0),
		uintptr(unsafe.Pointer(&AprimaryGroupSize)),
	)
	// Check buffer sanity
	if AsecDesSize == 0 {
		return nil, err
	}
	// Make buffers
	AsecDes := make([]uint16, AsecDesSize)
	Adacl := make([]uint16, AdaclSize)
	Asacl := make([]uint16, AsaclSize)
	Aowner := make([]uint16, AownerSize)
	AprimaryGroup := make([]uint16, AprimaryGroupSize)
	// Final call
	r1, _, err = procMakeAbsoluteSD.Call(
		uintptr(unsafe.Pointer(&selfRelative[0])),
		uintptr(unsafe.Pointer(&AsecDes[0])),
		uintptr(unsafe.Pointer(&AsecDesSize)),
		uintptr(unsafe.Pointer(&Adacl[0])),
		uintptr(unsafe.Pointer(&AdaclSize)),
		uintptr(unsafe.Pointer(&Asacl[0])),
		uintptr(unsafe.Pointer(&AsaclSize)),
		uintptr(unsafe.Pointer(&Aowner[0])),
		uintptr(unsafe.Pointer(&AownerSize)),
		uintptr(unsafe.Pointer(&AprimaryGroup[0])),
		uintptr(unsafe.Pointer(&AprimaryGroupSize)),
	)
	if r1 == 0 {
		return nil, err
	}
	return AsecDes, nil
}

// MakeSelfRelativeSD makes an absolute security descriptor out of a self-relative
func MakeSelfRelativeSD(absoluteSD []uint16) ([]uint16, error) {
	var RsecDesSize uint32
	// Get sizes
	r1, _, err := procMakeSelfRelativeSD.Call(
		uintptr(unsafe.Pointer(&absoluteSD[0])),
		uintptr(0),
		uintptr(unsafe.Pointer(&RsecDesSize)),
	)
	// Check buffer sanity
	if RsecDesSize == 0 {
		return nil, err
	}
	// Make buffers
	RsecDes := make([]uint16, RsecDesSize)
	// Final call
	r1, _, err = procMakeSelfRelativeSD.Call(
		uintptr(unsafe.Pointer(&absoluteSD[0])),
		uintptr(unsafe.Pointer(&RsecDes[0])),
		uintptr(unsafe.Pointer(&RsecDesSize)),
	)
	if r1 == 0 {
		return nil, err
	}
	return RsecDes, nil
}
