//go:build windows && amd64
// +build windows,amd64

package winapi

import (
	"fmt"
	"log"
)

func ExampleFirewallRuleAdd() {
	ok, err := FirewallRuleAdd("SQL Server", "Main static SQL Server port 1433", "SQL services", "1433",
		NET_FW_IP_PROTOCOL_TCP, NET_FW_PROFILE2_DOMAIN|NET_FW_PROFILE2_PRIVATE)
	if ok {
		fmt.Println("Firewall rule created!")
	} else {
		if err != nil {
			fmt.Printf("can't enable SQL Server remote access, err: %s\n", err)
		} else {
			fmt.Println("rule already exists")
		}
	}
}

func ExampleFirewallRuleAddApplication() {
	_, err := FirewallRuleAddApplication("SQL Browser App", "App rule for SQL Browser", "SQL Services",
		`%ProgramFiles% (x86)\Microsoft SQL Server\90\Shared\sqlbrowser.exe`, NET_FW_PROFILE2_CURRENT)
	if err != nil {
		log.Fatalln(err)
	}
	FirewallRuleDelete("SQL Browser App") // check error!
}

func ExampleFirewallPingEnable() {
	if _, err := FirewallPingEnable("Allow ping", "Start answering echo requests", "", "", NET_FW_PROFILE2_DOMAIN); err != nil {
		fmt.Println(err)
	}
	// To disable, delete the rule
	if _, err := FirewallRuleDelete("Allow ping"); err != nil {
		fmt.Println(err)
	}
	FirewallRuleDelete("Allow ping") // check error!
}

func ExampleFirewallRulesGet_onlyEnabledInPrivateProfile() {
	// let's get rules which are active in given profile
	rr, err := FirewallRulesGet()
	if err != nil {
		panic(err) // panic used only for brevity
	}
	for _, r := range rr {
		if r.Profiles&NET_FW_PROFILE2_PRIVATE != 0 && r.Enabled {
			fmt.Println(r.Name)
		}
	}
}

func ExampleFirewallRuleAddAdvanced_iPv6Ping() {
	if !isAdmin() {
		fmt.Println("elevated shell is required!")
	}
	r := FWRule{
		Name:              "Allow IPv6 ping",
		Description:       "My rule",
		Grouping:          "My group",
		Enabled:           true,
		Protocol:          NET_FW_IP_PROTOCOL_ICMPv6,
		ICMPTypesAndCodes: "128:*", // https://www.iana.org/assignments/icmpv6-parameters/icmpv6-parameters.xhtml
	}

	// Enable IPv6 ping
	ok, err := FirewallRuleAddAdvanced(r)
	if !ok {
		if err != nil {
			fmt.Println(err)
		} else {
			fmt.Printf("FW rule with name %q already exists.\n", r.Name)
		}
	}
	if ok {
		fmt.Println("Rule added!")
	}
	// output: Rule added!
	FirewallRuleDelete("Allow IPv6 ping") // check error!
}

func ExampleFirewallRuleAddAdvanced_restrictedLocalPorts() {
	if !isAdmin() {
		fmt.Println("elevated shell is required!")
	}
	r := FWRule{
		Name:            "Application rule enabling incoming connections only on port 1234",
		Description:     "This is the same rule as created with FirewallRuleCreate",
		Grouping:        "My group",
		Enabled:         true,
		Protocol:        NET_FW_IP_PROTOCOL_TCP,
		LocalPorts:      "1234",
		ApplicationName: `C:\Test\myApp`,
		Profiles:        NET_FW_PROFILE2_PRIVATE | NET_FW_PROFILE2_DOMAIN, // let's enable it in 2 profiles
	}

	// Enable app rule restricted to port 1234 TCP
	ok, err := FirewallRuleAddAdvanced(r)
	if !ok {
		if err != nil {
			fmt.Println(err)
		} else {
			fmt.Printf("FW rule with name %q already exists.\n", r.Name)
		}
	}
	if ok {
		fmt.Println("Rule added!")
	}
	FirewallRuleDelete("Application rule enabling incoming connections only on port 1234") // check error!
	// output: Rule added!
}

func ExampleFirewallRuleAddAdvanced_serviceRule() {
	if !isAdmin() {
		fmt.Println("elevated shell is required!")
	}
	r := FWRule{
		Name:        "All all connection to SQL Server Browser service",
		Description: "This is rule created for specific service",
		Grouping:    "My group",
		Enabled:     true,
		Protocol:    NET_FW_IP_PROTOCOL_ANY,
		ServiceName: "SQLBrowser",
		Profiles:    NET_FW_PROFILE2_CURRENT, // let's enable it in currently used profiles
	}

	// Enable service rule
	ok, err := FirewallRuleAddAdvanced(r)
	if !ok {
		if err != nil {
			fmt.Println(err)
		} else {
			fmt.Printf("FW rule with name %q already exists.\n", r.Name)
		}
	}
	if ok {
		fmt.Println("Rule added!")
	}
	FirewallRuleDelete("All all connection to SQL Server Browser service") // check error!
	// output: Rule added!
}
