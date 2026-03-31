//go:build windows && amd64
// +build windows,amd64

package winapi

// WARNING!!! This test have to be run in elevated shell.
// Otherwise "Exception occurred" error will raise on avery action.

import (
	"os"
	"reflect"
	"testing"
)

func getTestRule() FWRule {
	return FWRule{
		Description:       "This is win64api test rule.",
		Grouping:          "TestRuleGroup",
		Protocol:          NET_FW_IP_PROTOCOL_TCP,
		Profiles:          NET_FW_PROFILE2_DOMAIN,
		LocalPorts:        "6000",
		RemotePorts:       "22000",
		LocalAddresses:    "127.0.0.1",
		RemoteAddresses:   "192.168.2.0/255.255.255.0", // /24
		ICMPTypesAndCodes: "8:*",
		InterfaceTypes:    "LAN",
		ApplicationName:   `C:\Test\mysupertestapp.exe`,
		Enabled:           true,
		EdgeTraversal:     false,
		Direction:         NET_FW_RULE_DIR_IN,
		Action:            NET_FW_ACTION_ALLOW,
	}
}

func isAdmin() bool {
	_, err := os.Open(`\\.\PHYSICALDRIVE0`)
	if err != nil {
		return false
	}
	return true
}

func TestCreatingRule(t *testing.T) {
	if !isAdmin() {
		t.Fatal("run test in elevated shell (Run as administrator)!")
	}
	rule := getTestRule()
	rule.Name = "TestRule001 Port rule"
	rule.ICMPTypesAndCodes = ""
	rule.RemotePorts = "*"
	rule.RemoteAddresses = "*"
	rule.LocalAddresses = "*"
	rule.InterfaceTypes = "All"
	rule.ApplicationName = ""
	ok, err := FirewallRuleAdd(rule.Name, rule.Description, rule.Grouping, rule.LocalPorts, rule.Protocol, rule.Profiles)
	if !ok {
		if err != nil {
			t.Errorf("problem with adding FW rule: %v", err)
		} else {
			t.Errorf("rule already exists")
		}
	}
	fwRuleCheckAndDelete(rule, t)
}

func TestFirewallRuleAddApplication(t *testing.T) {
	if !isAdmin() {
		t.Fatal("run test in elevated shell (Run as administrator)!")
	}
	rule := getTestRule()
	rule.Name = "TestRule002 Application rule"
	rule.ICMPTypesAndCodes = ""
	rule.LocalPorts = ""
	rule.RemotePorts = ""
	rule.RemoteAddresses = "*"
	rule.LocalAddresses = "*"
	rule.InterfaceTypes = "All"
	rule.Protocol = NET_FW_IP_PROTOCOL_ANY
	ok, err := FirewallRuleAddApplication(rule.Name, rule.Description, rule.Grouping, rule.ApplicationName, rule.Profiles)
	if !ok {
		if err != nil {
			t.Errorf("problem with adding FW application rule: %v", err)
		} else {
			t.Errorf("rule already exists")
		}
	}
	fwRuleCheckAndDelete(rule, t)
}

func TestFirewallPingEnable(t *testing.T) {
	if !isAdmin() {
		t.Fatal("run test in elevated shell (Run as administrator)!")
	}
	rule := getTestRule()
	rule.Name = "TestRule003 Enable Ping response"
	rule.LocalPorts = ""
	rule.RemotePorts = ""
	rule.LocalAddresses = "*"
	rule.InterfaceTypes = "All"
	rule.Protocol = NET_FW_IP_PROTOCOL_ICMPv4
	rule.Profiles = NET_FW_PROFILE2_PRIVATE
	rule.ApplicationName = ""
	ok, err := FirewallPingEnable(rule.Name, rule.Description, rule.Grouping, rule.RemoteAddresses, rule.Profiles)
	if !ok {
		if err != nil {
			t.Errorf("problem with adding FW Ping rule: %v", err)
		} else {
			t.Errorf("rule already exists")
		}
	}
	fwRuleCheckAndDelete(rule, t)
}

// TestFirewallRuleGet will probably work only on Windows english localisation
func TestFirewallRuleGet(t *testing.T) {
	var empty FWRule
	//name := "@FirewallAPI.dll,-25326"
	name := "Core Networking - Teredo (UDP-In)"
	r, err := FirewallRuleGet(name)
	if r == empty {
		if err != nil {
			t.Errorf("problem with getting rule: %v", err)
		} else {
			t.Errorf("rule %q not found", name)
		}
	}
}

func fwRuleCheckAndDelete(rule FWRule, t *testing.T) {
	rules, err := FirewallRulesGet()
	if err != nil {
		t.Errorf("error geting rules: %v", err)
	}
	for _, r := range rules {
		if r.Name == rule.Name {
			if !reflect.DeepEqual(r, rule) {
				t.Errorf("returned rules is different then expected:\n%+v, returned:\n%+v", rule, r)
			}
		}
	}
	ok, err := FirewallRuleDelete(rule.Name)
	if !ok {
		if err != nil {
			t.Errorf("error deleting test FW rule, err: %v", err)
		} else {
			t.Errorf("rule do not exists, so not deleted")
		}
	}
}
