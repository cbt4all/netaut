package passh

import (
	"errors"
	"log"
	"net"
)

// TestRouteFibInterfaceCmd ...
func TestRouteFibInterfaceCmd(s, ip string) string {
	// s is Virtual Router
	if net.ParseIP(ip) == nil {
		log.Fatal(ip + " is not a valid IP")
	}
	return "test routing fib-lookup virtual-router " + s + " ip " + ip
}

// ShowInterfaceCmd ...
func ShowInterfaceCmd(s string) string {
	// s is Interface Name
	return "show interface " + s + " "
}

// TestSecurityPolicyMatchCmd ...
func TestSecurityPolicyMatchCmd(cfg [7]string) (string, error) {
	// test security-policy-match protocol 6 from Mgmt-Outside to Mgmt-HP source 10.115.0.136 destination 10.115.233.21 destination-port 443 application ssh
	// cfg[0] is Protocol Number (e.g. 6)
	// cfg[1] is Source Zone
	// cfg[2] is Destination Zone
	// cfg[3] is Source IP
	// cfg[4] is Destination IP
	// cfg[5] is Destination Port
	// cfg[6] is Application

	err := errors.New("nil")
	err = nil
	var result string

	if cfg[0] == "" {
		err = errors.New("Fist parameter should be protocol number!\n")
		return "", err
	}
	if cfg[1] == "" {
		err = errors.New("Second parameter should be Source Zone!\n")
		return "", err
	}
	if cfg[2] == "" {
		err = errors.New("Fist parameter should be Destination Zone!\n")
		return "", err
	}
	if cfg[3] == "" {
		err = errors.New("Fist parameter should be Source IP!\n")
		return "", err
	}
	if cfg[4] == "" {
		err = errors.New("Fist parameter should be Destination IP!\n")
		return "", err
	}

	result = "test security-policy-match protocol " + cfg[0] + " from " + cfg[1] + " to " + cfg[2] + " source " + cfg[3] + " destination " + cfg[4]

	if cfg[5] != "" {
		result = result + " destination-port " + cfg[5]
	}
	if cfg[6] != "nil" {
		result = result + " application " + cfg[6]
	}

	return result, err
}
