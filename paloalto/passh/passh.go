package passh

import (
	"errors"
	"log"
	"net"
)

// TestRouteFibLookupCmd generates the command 'test routing fib-lookup virtual-router <virtual-router> ip <ip-address>'
// on the given <virtual-router> and <ip-address>.
// vr is Virtual Router
func TestRouteFibLookupCmd(vr, ip string) string {

	if net.ParseIP(ip) == nil {
		log.Fatal(ip + " is not a valid IP")
	}

	return "test routing fib-lookup virtual-router " + vr + " ip " + ip
}

// ShowInterfaceCmd generates the command 'show interface <interface>' on the given <interface>.
// s is Interface Name
func ShowInterfaceCmd(s string) string {

	return "show interface " + s + " "
}

// TestSecurityPolicyMatchCmd generates the command ' test security-policy-match protocol 6 from <source-zone> to <destination-zone> source <source-ip-address>
// destination <destination-ip-address> destination-port <destination-port> application <application-name>
// cfg[0] is Protocol Number (e.g. 6)
// cfg[1] is Source Zone
// cfg[2] is Destination Zone
// cfg[3] is Source IP
// cfg[4] is Destination IP
// cfg[5] is Destination Port
// cfg[6] is Application
func TestSecurityPolicyMatchCmd(cfg [7]string) (string, error) {

	outErr := errors.New("nil")
	outErr = nil
	var result string

	if cfg[0] == "" {
		outErr = errors.New("Fist parameter should be protocol number!\n")
		return "", outErr
	}
	if cfg[1] == "" {
		outErr = errors.New("Second parameter should be Source Zone!\n")
		return "", outErr
	}
	if cfg[2] == "" {
		outErr = errors.New("Fist parameter should be Destination Zone!\n")
		return "", outErr
	}
	if cfg[3] == "" {
		outErr = errors.New("Fist parameter should be Source IP!\n")
		return "", outErr
	}
	if cfg[4] == "" {
		outErr = errors.New("Fist parameter should be Destination IP!\n")
		return "", outErr
	}
	if cfg[5] == "" {
		outErr = errors.New("Fist parameter should be Destination Port!\n")
		return "", outErr
	}

	result = "test security-policy-match"
	result = result + " protocol " + cfg[0]
	result = result + " from " + cfg[1] + " to " + cfg[2]
	result = result + " source " + cfg[3] + " destination " + cfg[4]
	result = result + " destination-port " + cfg[5]

	if cfg[6] != "nil" {
		result = result + " application " + cfg[6]
	}

	return result, outErr
}
