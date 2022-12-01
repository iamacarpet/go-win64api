package winapi

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/saksham-ghimire/go-win64api/shared"
)

func (f *FWRule) ValidateFWRule() (bool, error) {

	// validate ips
	localAddresses := strings.Split(f.LocalAddresses, ",")
	remoteAddresses := strings.Split(f.RemoteAddresses, ",")

	for _, ip := range localAddresses {
		if !validIP(ip) && !validIpWithSubnet(ip) {
			fmt.Println(validIpWithSubnet(ip), validIP(ip))
			return false, errors.New("invalid ip string")
		}
	}
	for _, ip := range remoteAddresses {
		if ip != "" {
			if !validIP(ip) && !validIpWithSubnet(ip) {
				return false, errors.New("invalid ip string")
			}
		}

	}

	// validate ports
	localPorts := strings.Split(f.LocalPorts, ",")
	remotePorts := strings.Split(f.RemotePorts, ",")
	for _, port := range localPorts {
		if port != "" {
			if !validPort(port) {
				return false, errors.New("invalid port number")
			}
		}
	}
	for _, port := range remotePorts {
		if port != "" {
			if !validPort(port) {
				return false, errors.New("invalid port number")
			}
		}
	}

	// validate protocol
	if _, available := shared.DefinedProtocols[int(f.Protocol)]; !available {
		return false, errors.New("invalid protocol")
	}
	// validate direction
	if _, available := shared.DefinedDirection[int(f.Direction)]; !available {
		return false, errors.New("invalid direction")
	}
	// validate action
	if _, available := shared.DefinedAction[int(f.Action)]; !available {
		return false, errors.New("invalid action")
	}
	// validate profile
	if _, available := shared.DefinedProfile[int(f.Profiles)]; !available {
		return false, errors.New("invalid profile")
	}

	// validateInterfaces
	interfaces := strings.Split(f.InterfaceTypes, ",")
	for _, intFace := range interfaces {
		if _, available := shared.DefinedInterfaces[intFace]; !available {
			return false, errors.New("invalid profile")
		}
	}

	return true, nil
}

func validIP(ip string) bool {
	if ip == "*" {
		return true
	}
	if net.ParseIP(ip) == nil {
		return false
	} else {
		return true
	}
}

func validIpWithSubnet(ip string) bool {
	addresses := strings.Split(ip, "/")
	if len(addresses) != 2 {
		return false
	}
	ip, sub := addresses[0], addresses[1]
	subnet, err := strconv.Atoi(sub)
	if err != nil {
		return false
	}
	if validIP(ip) && (subnet >= 8 && subnet <= 32) {
		return true
	}
	return false
}

func validPort(port string) bool {
	if port == "*" {
		return true
	}
	portNum, err := strconv.Atoi(port)
	if err != nil {
		return false
	}
	if portNum > 0 && portNum < 65536 {
		return true
	}
	return false
}
