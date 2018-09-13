// +build windows,amd64

package winapi

import (
	"fmt"
	"runtime"

	ole "github.com/go-ole/go-ole"
	"github.com/go-ole/go-ole/oleutil"
)

const (
	NET_FW_IP_PROTOCOL_TCP = 6
	NET_FW_ACTION_ALLOW    = 1
)

func FirewallRuleCreate(name, description, group, appPath, port string, protocol uint) (bool, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	ole.CoInitializeEx(0, ole.COINIT_APARTMENTTHREADED|ole.COINIT_SPEED_OVER_MEMORY)
	defer ole.CoUninitialize()

	unknown, err := oleutil.CreateObject("HNetCfg.FwPolicy2")
	if err != nil {
		return false, fmt.Errorf("Failed to create FwPolicy Object: %s", err)
	}
	defer unknown.Release()

	fwPolicy, err := unknown.QueryInterface(ole.IID_IDispatch)
	if err != nil {
		return false, fmt.Errorf("Failed to create FwPolicy Object (2): %s", err)
	}
	defer fwPolicy.Release()

	currentProfiles, err := oleutil.GetProperty(fwPolicy, "CurrentProfileTypes")
	if err != nil {
		return false, fmt.Errorf("Failed to get CurrentProfiles: %s", err)
	}
	unknownRules, err := oleutil.GetProperty(fwPolicy, "Rules")
	if err != nil {
		return false, fmt.Errorf("Failed to get Rules: %s", err)
	}
	rules := unknownRules.ToIDispatch()

	if ok, err := FirewallRuleExistsByName(rules, name); err != nil {
		return false, fmt.Errorf("Error while checking rules for dulicate: %s", err)
	} else if ok {
		return false, nil
	}

	unknown2, err := oleutil.CreateObject("HNetCfg.FWRule")
	if err != nil {
		return false, fmt.Errorf("Error creating Rule object: %s", err)
	}
	defer unknown2.Release()

	fwRule, err := unknown2.QueryInterface(ole.IID_IDispatch)
	if err != nil {
		return false, fmt.Errorf("Error creating Rule object (2): %s", err)
	}
	defer fwRule.Release()

	if _, err := oleutil.PutProperty(fwRule, "Name", name); err != nil {
		return false, fmt.Errorf("Error setting property (Name) of Rule: %s", err)
	}
	if _, err := oleutil.PutProperty(fwRule, "Description", description); err != nil {
		return false, fmt.Errorf("Error setting property (Description) of Rule: %s", err)
	}
	if _, err := oleutil.PutProperty(fwRule, "Applicationname", appPath); err != nil {
		return false, fmt.Errorf("Error setting property (Applicationname) of Rule: %s", err)
	}
	if _, err := oleutil.PutProperty(fwRule, "Protocol", protocol); err != nil {
		return false, fmt.Errorf("Error setting property (Protocol) of Rule: %s", err)
	}
	if _, err := oleutil.PutProperty(fwRule, "LocalPorts", port); err != nil {
		return false, fmt.Errorf("Error setting property (LocalPorts) of Rule: %s", err)
	}
	if _, err := oleutil.PutProperty(fwRule, "Enabled", true); err != nil {
		return false, fmt.Errorf("Error setting property (Enabled) of Rule: %s", err)
	}
	if _, err := oleutil.PutProperty(fwRule, "Grouping", group); err != nil {
		return false, fmt.Errorf("Error setting property (Grouping) of Rule: %s", err)
	}
	if _, err := oleutil.PutProperty(fwRule, "Profiles", currentProfiles); err != nil {
		return false, fmt.Errorf("Error setting property (Profiles) of Rule: %s", err)
	}
	if _, err := oleutil.PutProperty(fwRule, "Action", NET_FW_ACTION_ALLOW); err != nil {
		return false, fmt.Errorf("Error setting property (Action) of Rule: %s", err)
	}

	if _, err := oleutil.CallMethod(rules, "Add", fwRule); err != nil {
		return false, fmt.Errorf("Error adding Rule: %s", err)
	}

	return true, nil
}

func FirewallRuleExistsByName(rules *ole.IDispatch, name string) (bool, error) {
	enumProperty, err := rules.GetProperty("_NewEnum")
	if err != nil {
		return false, fmt.Errorf("Failed to get enumeration property on Rules: %s", err)
	}
	defer enumProperty.Clear()

	enum, err := enumProperty.ToIUnknown().IEnumVARIANT(ole.IID_IEnumVariant)
	if err != nil {
		return false, fmt.Errorf("Failed to cast enum to correct type: %s", err)
	}
	if enum == nil {
		return false, fmt.Errorf("can't get IEnumVARIANT, enum is nil")
	}

	for itemRaw, length, err := enum.Next(1); length > 0; itemRaw, length, err = enum.Next(1) {
		if err != nil {
			return false, fmt.Errorf("Failed to seek next Rule item: %s", err)
		}

		t, err := func() (bool, error) {
			item := itemRaw.ToIDispatch()
			defer item.Release()

			if item, err := oleutil.GetProperty(item, "Name"); err != nil {
				return false, fmt.Errorf("Failed to get Property (Name) of Rule")
			} else if item.ToString() == name {
				return true, nil
			}

			return false, nil
		}()

		if err != nil {
			return false, err
		} else if t {
			return true, nil
		}
	}

	return false, nil
}
