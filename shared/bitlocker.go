package shared

type BitLockerDeviceInfo struct {
	DeviceID           string
	PersistentVolumeID string
	DriveLetter        string
	ProtectionStatus   int32
	ConversionStatus   int32
	RecoveryKeys       []string
}
