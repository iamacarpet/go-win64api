//go:build windows && amd64
// +build windows,amd64

package winapi

import (
	"fmt"
	"time"

	"golang.org/x/sys/windows/registry"

	so "github.com/iamacarpet/go-win64api/shared"
)

func InstalledSoftwareList() ([]so.Software, error) {
	sw64, err := getSoftwareList(`SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`, "", "X64")
	if err != nil {
		return nil, err
	}
	sw32, err := getSoftwareList(`SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall`, "", "X32")
	if err != nil {
		return nil, err
	}
	k, err := registry.OpenKey(registry.USERS, "", registry.QUERY_VALUE|registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		return nil, err
	}
	defer k.Close()

	osUsers, err := k.ReadSubKeyNames(-1)
	if err != nil {
		return nil, err
	}

	swmap := make(map[string]bool)
	var swList []so.Software

	for _, sw := range sw64 {
		if !swmap[sw.DisplayName] {
			swList = append(swList, sw)
			swmap[sw.DisplayName] = true
		}
	}
	for _, sw := range sw32 {
		if !swmap[sw.DisplayName] {
			swList = append(swList, sw)
			swmap[sw.DisplayName] = true
		}
	}

	for _, osUser := range osUsers {
		userSoftwareList64, err := getSoftwareList(`SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`, osUser, "X64")
		if err == nil {
			for _, sw := range userSoftwareList64 {
				if !swmap[sw.DisplayName] {
					swList = append(swList, sw)
					swmap[sw.DisplayName] = true
				}
			}
		}
		userSoftwareList32, err := getSoftwareList(`SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall`, osUser, "X32")
		if err == nil {
			for _, sw := range userSoftwareList32 {
				if !swmap[sw.DisplayName] {
					swList = append(swList, sw)
					swmap[sw.DisplayName] = true
				}
			}
		}
		userDataSoftwareList64, err := getSoftwareList(`SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData`, osUser, "X64")
		if err == nil {
			for _, sw := range userDataSoftwareList64 {
				if !swmap[sw.DisplayName] {
					swList = append(swList, sw)
					swmap[sw.DisplayName] = true
				}
			}
		}
		userDataSoftwareList32, err := getSoftwareList(`SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Installer\UserData`, osUser, "X32")
		if err == nil {
			for _, sw := range userDataSoftwareList32 {
				if !swmap[sw.DisplayName] {
					swList = append(swList, sw)
					swmap[sw.DisplayName] = true
				}
			}
		}
	}
	return swList, nil
}

func parseSoftware(rootKey registry.Key, path string) (so.Software, error) {
	sk, err := registry.OpenKey(rootKey, path, registry.QUERY_VALUE)
	if err != nil {
		return so.Software{}, fmt.Errorf("Error reading from registry `%s`: %s", path, err.Error())
	}
	defer sk.Close()

	dn, _, err := sk.GetStringValue("DisplayName")
	if err != nil {
		return so.Software{}, err
	}
	swv := so.Software{DisplayName: dn}

	if rootKey == registry.LOCAL_MACHINE {
		swv.RegKey = fmt.Sprintf(`HKLM\%s`, path)
	} else if rootKey == registry.USERS {
		swv.RegKey = fmt.Sprintf(`HKU\%s`, path)
	}

	dv, _, err := sk.GetStringValue("DisplayVersion")
	if err == nil {
		swv.DisplayVersion = dv
	}

	pub, _, err := sk.GetStringValue("Publisher")
	if err == nil {
		swv.Publisher = pub
	}

	id, _, err := sk.GetStringValue("InstallDate")
	if err == nil {
		swv.InstallDate, _ = time.Parse("20060102", id)
	}

	es, _, err := sk.GetIntegerValue("EstimatedSize")
	if err == nil {
		swv.EstimatedSize = es
	}

	cont, _, err := sk.GetStringValue("Contact")
	if err == nil {
		swv.Contact = cont
	}

	hlp, _, err := sk.GetStringValue("HelpLink")
	if err == nil {
		swv.HelpLink = hlp
	}

	isource, _, err := sk.GetStringValue("InstallSource")
	if err == nil {
		swv.InstallSource = isource
	}

	ilocaction, _, err := sk.GetStringValue("InstallLocation")
	if err == nil {
		swv.InstallLocation = ilocaction
	}

	ustring, _, err := sk.GetStringValue("UninstallString")
	if err == nil {
		swv.UninstallString = ustring
	}

	mver, _, err := sk.GetIntegerValue("VersionMajor")
	if err == nil {
		swv.VersionMajor = mver
	}

	mnver, _, err := sk.GetIntegerValue("VersionMinor")
	if err == nil {
		swv.VersionMinor = mnver
	}
	return swv, nil
}

func getSoftwareList(baseKey, user, arch string) ([]so.Software, error) {
	rootKey := registry.LOCAL_MACHINE
	if user != "" {
		rootKey = registry.USERS
		baseKey = user + `\` + baseKey
	}
	k, err := registry.OpenKey(rootKey, baseKey, registry.QUERY_VALUE|registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		return nil, fmt.Errorf("Error reading from registry: %s", err.Error())
	}
	defer k.Close()

	swList := make([]so.Software, 0)

	subkeys, err := k.ReadSubKeyNames(-1)
	if err != nil {
		return nil, fmt.Errorf("Error reading subkey list from registry: %s", err.Error())
	}
	for _, sw := range subkeys {
		parsed, err := parseSoftware(rootKey, baseKey+`\`+sw)
		if err != nil {
			continue
		}
		parsed.Arch = arch
		swList = append(swList, parsed)
	}

	return swList, nil
}

func getUserDataSoftwareList(baseKey, user, arch string) ([]so.Software, error) {
	k, err := registry.OpenKey(registry.USERS, baseKey, registry.QUERY_VALUE|registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		return nil, fmt.Errorf("Error reading from registry: %s", err.Error())
	}
	defer k.Close()

	swList := make([]so.Software, 0)

	subkeys, err := k.ReadSubKeyNames(-1)
	if err != nil {
		return nil, fmt.Errorf("Error reading subkey list from registry: %s", err.Error())
	}
	for _, sw := range subkeys {
		parsed, err := parseSoftware(registry.LOCAL_MACHINE, baseKey+`\`+sw)
		if err != nil {
			continue
		}
		parsed.Arch = arch
		swList = append(swList, parsed)
	}
	return swList, nil
}
