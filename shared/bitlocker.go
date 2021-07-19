package shared

// BitLockerConversionStatus represents the GetConversionStatus method of Win32_EncryptableVolume
type BitLockerConversionStatus struct {
	ConversionStatus     uint32
	EncryptionPercentage uint32
	EncryptionFlags      uint32
	WipingStatus         uint32
	WipingPercentage     uint32
}

// Possible values for the value placed in the ConversionStatus field returned by the GetConversionStatus method of Win32_EncryptableVolume
const (
	FULLY_DECRYPTED = iota
	FULLY_ENCRYPTED
	ENCRYPTION_IN_PROGRESS
	DECRYPTION_IN_PROGRESS
	ENCRYPTION_PAUSED
	DECRYPTION_PAUSED
)

// Bitflags for the value placed in the EncryptionFlags field returned by the GetConversionStatus method of Win32_EncryptableVolume
const (
	DATA_ONLY      = 0x00000001
	ON_DEMAND_WIPE = 0x00000002
	SYNCHRONOUS    = 0x00010000
)

// Possible values for the value placed in the WipingStatus field returned by the GetConversionStatus method of Win32_EncryptableVolume
const (
	NOT_WIPED = iota
	WIPED
	WIPING_IN_PROGRESS
	WIPING_PAUSED
)

// BitLockerDeviceInfo contains the bitlocker state for a given device
type BitLockerDeviceInfo struct {
	DeviceID           string
	PersistentVolumeID string
	DriveLetter        string
	ProtectionStatus   uint32
	ConversionStatus   uint32
	RecoveryKeys       []string
}
