package passh

import (
	"errors"
	"log"
	"net"

	"github.com/cbt4all/netaut/paloalto"
)

// TestRouteFibLookupCmd generates the command 'test routing fib-lookup virtual-router <virtual-router> ip <ip-address>'
// on the given <virtual-router> and <ip-address>. This function gets:
// dip is Destination IP
// vr is Virtual Router
func TestRouteFibLookupCmd(vr, dip string) string {

	if net.ParseIP(dip) == nil {
		log.Fatal(dip + " is not a valid IP")
	}

	return "test routing fib-lookup virtual-router " + vr + " ip " + dip
}

// ParseInterfaceFromFIB gets an XML then parses it and returns to get only interface name. 
func ParseInterfaceFromFIB(s string) (string, error) {

	// Parse the output
	fbr, err := paloalto.ParseXMLFibResult(s)
	if err != nil {
		return "", err
	}

	return fbr.Result.Interface, nil
}

// ShowInterfaceCmd generates the command 'show interface <interface>' on the given <interface>.
// Intrfc is Interface Name
func ShowInterfaceCmd(Intrfc string) string {
	return "show interface " + Intrfc + " "
}

// ParseZoneFromInterface gets an XML then parses it and returns to get only Zone name of the given interface.
func ParseZoneFromInterface(s string) (string, error) {

	// Parse the output
	ifnet, err := paloalto.ParseXMLIfNet(s)
	if err != nil {
		return "", nil
	}
	return ifnet.Result.Ifnet.Zone, nil
}

// TestSecurityPolicyMatchCmd generates the command ' test security-policy-match protocol 6 from <source-zone> to <destination-zone> source <source-ip-address>
// destination <destination-ip-address> destination-port <destination-port> application <application-name>. This function gets cfg which is an 7-cell array in which:
// cfg[0] is Protocol Number (e.g. 6)
// cfg[1] is Source Zone
// cfg[2] is Destination Zone
// cfg[3] is Source IP
// cfg[4] is Destination IP
// cfg[5] is Destination Port
// cfg[6] is Application
func TestSecurityPolicyMatchCmd(cfg [7]string) (result string, err error) {

	if cfg[0] == "" {
		return "", errors.New("Fist parameter should be protocol number!\n")
	}
	if cfg[1] == "" {
		return "", errors.New("Second parameter should be Source Zone!\n")
	}
	if cfg[2] == "" {
		return "", errors.New("Third parameter should be Destination Zone!\n")
	}
	if cfg[3] == "" {
		return "", errors.New("Fourth parameter should be Source IP!\n")
	}
	if cfg[4] == "" {
		return "", errors.New("Fifth parameter should be Destination IP!\n")
	}
	if cfg[5] == "" {
		return "", errors.New("Sixth parameter should be Destination Port!\n")
	}

	result = "test security-policy-match"
	result = result + " protocol " + cfg[0]
	result = result + " from " + cfg[1] + " to " + cfg[2]
	result = result + " source " + cfg[3] + " destination " + cfg[4]
	result = result + " destination-port " + cfg[5]

	if cfg[6] != "nil" {
		result = result + " application " + cfg[6]
	}

	return result, nil
}

// ParseActionFromPolicyMatch gets an XML then parses it and returns to get only the Action part of given Test Security Policy Match result
func ParseActionFromPolicyMatch(s string) (string, error) {

	// Parse the output
	plcm, err := paloalto.ParseXMLPolicyMatch(s)
	if err != nil {
		return "", err
	}

	return plcm.Result.Rules.Entry.Action, nil
}
