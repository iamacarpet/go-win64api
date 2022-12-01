package winapi

import (
	"testing"
)

func TestValidators(t *testing.T) {
	rule1 := &FWRule{
		LocalAddresses:  "192.168.101.9/24,192.168.101.12/24",
		RemoteAddresses: "10.10.10.1",
		RemotePorts:     "15,20",
		LocalPorts:      "*",
		InterfaceTypes:  "LAN,Wireless",
		Protocol:        1,
		Action:          1,
		Direction:       1,
		Profiles:        1,
	}

	v, err := rule1.ValidateFWRule()
	if err != nil {
		t.Logf("testing case failed with error %v", err)
		t.Fail()
	}
	if v != true {
		t.Logf("testing case failed")
		t.Fail()
	}
}
