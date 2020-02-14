// +build windows,amd64

package winapi

import (
	"fmt"
	"syscall"
	"unsafe"
)

var (
	modUserenv                          = syscall.NewLazyDLL("Userenv.dll")
	procGetDefaultUserProfileDirectoryW = modUserenv.NewProc("GetDefaultUserProfileDirectoryW")
	procGetProfilesDirectoryW           = modUserenv.NewProc("GetProfilesDirectoryW")
	userCreateProfile                   = modUserenv.NewProc("CreateProfile")
)

// GetDefaultUserProfileDirectory returns the path to the directory in which the
// default user's profile is stored.
//
// See: https://docs.microsoft.com/en-us/windows/desktop/api/userenv/nf-userenv-getdefaultuserprofiledirectoryw
func GetDefaultUserProfileDirectory() (string, error) {
	var bufferSize uint32

	r1, _, err := procGetDefaultUserProfileDirectoryW.Call(
		uintptr(0),                           // lpProfileDir = NULL,
		uintptr(unsafe.Pointer(&bufferSize)), // lpcchSize = &bufferSize
	)
	// The first call always "fails" due to the buffer being NULL, but it should
	// have stored the needed buffer size in the variable bufferSize.

	// Sanity check to make sure bufferSize is sane.
	if bufferSize == 0 {
		return "", err
	}

	// bufferSize now contains the size of the buffer needed to contain the path.
	buffer := make([]uint16, bufferSize)
	r1, _, err = procGetDefaultUserProfileDirectoryW.Call(
		uintptr(unsafe.Pointer(&buffer[0])),  // lpProfileDir = &buffer
		uintptr(unsafe.Pointer(&bufferSize)), // lpcchSize = &bufferSize
	)
	if r1 == 0 {
		return "", err
	}
	return syscall.UTF16ToString(buffer), nil
}

// GetProfilesDirectory returns the path to the directory in which user profiles
// are stored. Profiles for new users are stored in subdirectories.
//
// See: https://docs.microsoft.com/en-us/windows/desktop/api/userenv/nf-userenv-getprofilesdirectoryw
func GetProfilesDirectory() (string, error) {
	var bufferSize uint32

	r1, _, err := procGetProfilesDirectoryW.Call(
		uintptr(0),                           // lpProfileDir = NULL,
		uintptr(unsafe.Pointer(&bufferSize)), // lpcchSize = &bufferSize
	)
	// The first call always "fails" due to the buffer being NULL, but it should
	// have stored the needed buffer size in the variable bufferSize.

	// Sanity check to make sure bufferSize is sane.
	if bufferSize == 0 {
		return "", err
	}

	// bufferSize now contains the size of the buffer needed to contain the path.
	buffer := make([]uint16, bufferSize)
	r1, _, err = procGetProfilesDirectoryW.Call(
		uintptr(unsafe.Pointer(&buffer[0])),  // lpProfileDir = &buffer
		uintptr(unsafe.Pointer(&bufferSize)), // lpcchSize = &bufferSize
	)
	if r1 == 0 {
		return "", err
	}
	return syscall.UTF16ToString(buffer), nil
}

// CreateUserProfile creates the user profile.
func CreateUserProfile(username string) (string, error) {
	// Get raw Sid
	rawSid, err := GetRawSidForAccountName(username)
	if err != nil {
		return "", fmt.Errorf("Unable to get raw ssid")
	}
	// Convert Sid to string
	sid, err := ConvertRawSidToStringSid(rawSid)
	if err != nil {
		return "", fmt.Errorf("Unable to convert raw ssid to string")
	}
	// Convert strings
	usernamePtr, err := syscall.UTF16PtrFromString(username)
	if err != nil {
		return "", fmt.Errorf("failed to convert user name to UTF16: %v", err)
	}
	sidPtr, err := syscall.UTF16PtrFromString(sid)
	if err != nil {
		return "", fmt.Errorf("failed to convert user name to UTF16: %v", err)
	}
	// Set buffer size
	var bufferSize uint32 = 128
	// bufferSize now contains the size of the buffer needed to contain the path.
	buffer := make([]uint16, bufferSize)
	// Create Profile
	r1, _, err := userCreateProfile.Call(
		uintptr(unsafe.Pointer(sidPtr)),
		uintptr(unsafe.Pointer(usernamePtr)),
		uintptr(unsafe.Pointer(&buffer[0])),
		uintptr(bufferSize),
	)
	if r1 != 0 {
		return "", err
	}
	return syscall.UTF16ToString(buffer), nil
}
