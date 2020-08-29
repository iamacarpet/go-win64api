// +build windows,amd64

package winapi

import (
	"fmt"

	ole "github.com/go-ole/go-ole"
	"github.com/go-ole/go-ole/oleutil"
	so "github.com/kumako/go-win64api/shared"
)

func GetBitLockerRecoveryInfo() ([]*so.BitLockerDeviceInfo, error) {
	return getBitLockerRecoveryInfoInternal("")
}

func GetBitLockerRecoveryInfoForDrive(driveLetter string) (*so.BitLockerDeviceInfo, error) {
	result, err := getBitLockerRecoveryInfoInternal(" WHERE DriveLetter = '" + driveLetter + "'")
	if err != nil {
		return nil, err
	}

	if len(result) < 1 {
		return nil, fmt.Errorf("Error getting BitLocker Recovery Info, Drive not found: %s", driveLetter)
	} else if len(result) > 1 {
		return nil, fmt.Errorf("Error getting BitLocker Recovery Info, Too many results: %s", driveLetter)
	} else {
		return result[0], err
	}
}

func getBitLockerRecoveryInfoInternal(where string) ([]*so.BitLockerDeviceInfo, error) {
	ole.CoInitialize(0)
	defer ole.CoUninitialize()

	unknown, err := oleutil.CreateObject("WbemScripting.SWbemLocator")
	if err != nil {
		return nil, fmt.Errorf("Unable to create initial object, %s", err.Error())
	}
	defer unknown.Release()
	wmi, err := unknown.QueryInterface(ole.IID_IDispatch)
	if err != nil {
		return nil, fmt.Errorf("Unable to create initial object, %s", err.Error())
	}
	defer wmi.Release()
	serviceRaw, err := oleutil.CallMethod(wmi, "ConnectServer", nil, `\\.\ROOT\CIMV2\Security\MicrosoftVolumeEncryption`)
	if err != nil {
		return nil, fmt.Errorf("Permission Denied - %s", err)
	}
	service := serviceRaw.ToIDispatch()
	defer service.Release()

	resultRaw, err := oleutil.CallMethod(service, "ExecQuery", "SELECT * FROM Win32_EncryptableVolume"+where)
	if err != nil {
		return nil, fmt.Errorf("Unable to execute query while getting BitLocker info. %s", err.Error())
	}
	result := resultRaw.ToIDispatch()
	defer result.Release()

	retBitLocker := []*so.BitLockerDeviceInfo{}

	countVar, err := oleutil.GetProperty(result, "Count")
	if err != nil {
		return nil, fmt.Errorf("Unable to get property Count while processing BitLocker info. %s", err.Error())
	}
	count := int(countVar.Val)

	for i := 0; i < count; i++ {
		retData, err := bitlockerRecoveryInfo(result, i)
		if err != nil {
			return nil, err
		}

		retBitLocker = append(retBitLocker, retData)
	}

	return retBitLocker, nil
}

func bitlockerRecoveryInfo(result *ole.IDispatch, i int) (*so.BitLockerDeviceInfo, error) {
	itemRaw, err := oleutil.CallMethod(result, "ItemIndex", i)
	if err != nil {
		return nil, fmt.Errorf("Failed to fetch result row while processing BitLocker info. %s", err.Error())
	}
	item := itemRaw.ToIDispatch()
	defer item.Release()

	retData := &so.BitLockerDeviceInfo{
		RecoveryKeys: []string{},
	}

	resDeviceID, err := oleutil.GetProperty(item, "DeviceID")
	if err != nil {
		return nil, fmt.Errorf("Error while getting property DeviceID from BitLocker info. %s", err.Error())
	}
	retData.DeviceID = resDeviceID.ToString()

	resPersistentVolumeID, err := oleutil.GetProperty(item, "PersistentVolumeID")
	if err != nil {
		return nil, fmt.Errorf("Error while getting property PersistentVolumeID from BitLocker info. %s", err.Error())
	}
	retData.PersistentVolumeID = resPersistentVolumeID.ToString()

	resDriveLetter, err := oleutil.GetProperty(item, "DriveLetter")
	if err != nil {
		return nil, fmt.Errorf("Error while getting property DriveLetter from BitLocker info. %s", err.Error())
	}
	retData.DriveLetter = resDriveLetter.ToString()

	resProtectionStatus, err := oleutil.GetProperty(item, "ProtectionStatus")
	if err != nil {
		return nil, fmt.Errorf("Error while getting property ProtectionStatus from BitLocker info. %s", err.Error())
	}
	var ok bool
	retData.ProtectionStatus, ok = resProtectionStatus.Value().(int32)
	if !ok {
		return nil, fmt.Errorf("Failed to parse ProtectionStatus from BitLocker info as uint32")
	}

	resConversionStatus, err := oleutil.GetProperty(item, "ConversionStatus")
	if err != nil {
		return nil, fmt.Errorf("Error while getting property ConversionStatus from BitLocker info. %s", err.Error())
	}
	ok = false
	retData.ConversionStatus, ok = resConversionStatus.Value().(int32)
	if !ok {
		return nil, fmt.Errorf("Failed to parse ConversionStatus from BitLocker info as uint32")
	}

	var keyProtectorResults ole.VARIANT
	ole.VariantInit(&keyProtectorResults)
	keyIDResultRaw, err := oleutil.CallMethod(item, "GetKeyProtectors", 3, &keyProtectorResults)
	if err != nil {
		return nil, fmt.Errorf("Unable to get Key Protectors while getting BitLocker info. %s", err.Error())
	} else if val, ok := keyIDResultRaw.Value().(int32); val != 0 || !ok {
		return nil, fmt.Errorf("Unable to get Key Protectors while getting BitLocker info. Return code %d", val)
	}
	keyProtectorValues := keyProtectorResults.ToArray().ToValueArray()

	for _, keyIDItemRaw := range keyProtectorValues {
		err = func() error {
			keyIDItem, ok := keyIDItemRaw.(string)
			if !ok {
				return fmt.Errorf("KeyProtectorID wasn't a string...")
			}

			var recoveryKey ole.VARIANT
			ole.VariantInit(&recoveryKey)
			recoveryKeyResultRaw, err := oleutil.CallMethod(item, "GetKeyProtectorNumericalPassword", keyIDItem, &recoveryKey)
			if err != nil {
				return fmt.Errorf("Unable to get Recovery Key while getting BitLocker info. %s", err.Error())
			} else if val, ok := recoveryKeyResultRaw.Value().(int32); val != 0 || !ok {
				return fmt.Errorf("Unable to get Recovery Key while getting BitLocker info. Return code %d", val)
			}

			retData.RecoveryKeys = append(retData.RecoveryKeys, recoveryKey.ToString())

			return nil
		}()
		if err != nil {
			return nil, err
		}
	}

	return retData, nil
}
