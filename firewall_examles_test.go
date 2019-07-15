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

func ExampleFirewallApplicationRuleAdd() {
	_, err := FirewallApplicationRuleAdd("SQL Browser App", "App rule for SQL Browser", "SQL Services",
		`%ProgramFiles% (x86)\Microsoft SQL Server\90\Shared\sqlbrowser.exe`, NET_FW_PROFILE2_CURRENT)
	if err != nil {
		log.Fatalln(err)
	}
}

func ExampleFirewallPingEnable() {
	if _, err := FirewallPingEnable("Allow ping", "Start answering echo requests", "", "", NET_FW_PROFILE2_DOMAIN); err != nil {
		fmt.Println(err)
	}
	// To disable, delete the rule
	if _, err := FirewallRuleDelete("Allow ping"); err != nil {
		fmt.Println(err)
	}
}

func ExampleFirewallGetRules() {
	// let's get rules which are active in given profile
	rr, err := FirewallGetRules()
	if err != nil {
		panic(err) // panic used only for brevity
	}
	for _, r := range rr {
		if r.Profiles&NET_FW_PROFILE2_PRIVATE != 0 && r.Enabled {
			fmt.Println(r.Name)
		}
	}
}
