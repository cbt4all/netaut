package palapi

import (
	"crypto/tls"
	"errors"
	"io/ioutil"
	"net/http"
)

type PClient struct {
	settings Settings
}

// Settings helps us to add settings on some function we are using. For example, if we want to use username and password to login to the firewalls or are we
// using token/Keys and based on this settings different authentication methods are use while logininig to firewall. Other things can be set here is to choose which
// type of APIs we want to use (REST API or XML API)
type Settings struct {
}

// TestRouteFibLookupApi generates REST/XML URL to be used to get firewall FIB information. This coresonds corresponds
// the command 'test routing fib-lookup virtual-router <virtual-router> ip <ip-address>' in CLI but here is used on firewall REST/XML API.
// Output will be in XML/Jason format, depends on how the parameter 'api' is used.
//
// What this function dose is to call either testRouteFibLookupRST or testRouteFibLookupXML to generate REST/XML URL respectively. So if TestRouteFibLookupApi
// is called by 'api=rest', testRouteFibLookupRST is used and if is called bu 'api=xml' testRouteFibLookupXML is called. The parameters are:
// fip is Firewall IP
// vr is Virtual-Router
// dip is Destination IP
// key is Token/Key should be takan manually from firewall
// api is the API type you want to use. For now it can be either 'rest' or 'xml'
func TestRouteFibLookup(fip, vr, dip, key, api string) ([]byte, error) {

	switch api {
	// To do: testRouteFibLookupRST
	/*
		case "rest":
			{
				return testRouteFibLookupRST(fip, vr, dip, key)
			}
	*/
	case "xml":
		{
			return testRouteFibLookupXML(fip, vr, dip, key)
		}
	default:
		{
			return nil, errors.New("wrong type of API is used.")
		}
	}

	return nil, errors.New("wrong type of API is used.")
}

// testRouteFibLookupXML generates an URL to be used to get firewall FIB information. This coresonds corresponds
// the command 'test routing fib-lookup virtual-router <virtual-router> ip <ip-address>' in CLI but here is used on firewall XML API.
// Output will be in XML format. In the command we have:
// fip is Firewall IP
// vr is Virtual-Router
// dip is Destination IP
// key is Token/Key should be takan manually from firewall
func testRouteFibLookupXML(fip, vr, dip, key string) ([]byte, error) {

	url := "https://" + fip + "/api/?type=op&cmd=<test><routing><fib-lookup><virtual-router>" + vr + "</virtual-router>"
	url = url + "<ip>" + dip + "</ip></fib-lookup></routing></test>&key=" + key

	method := "GET"

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	client := &http.Client{Transport: tr}

	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, errors.New("Error in http connection:" + resp.Status)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	return body, nil
}

// testRouteFibLookupRST generates REST URL to be used to get firewall FIB information. This coresonds corresponds
// the command 'test routing fib-lookup virtual-router <virtual-router> ip <ip-address>' in CLI but here is used on firewall REST API.
// Output will be in XML format. In the command we have:
// fip is Firewall IP
// vr is Virtual-Router
// dip is Destination IP
// key is Token/Key should be takan manually from firewall
func testRouteFibLookupRST(fip, vr, dip, key string) ([]byte, error) {
	// To Do
	// https://192.168.1.249/restapi/v9.1/Network/VirtualRouters
	return nil, nil
}

// ShowInterface generates REST/XML URL to be used to get firewall interface information. This coresonds corresponds
// the command 'show interface <interface>' in CLI but here is used on firewall REST/XML API.
// Output will be in XML/Jason format, depends on how the parameter 'api' is used.
// fip is Firewall IP
// Intrfc is the interface we want
// key is Token/Key should be takan manually from firewall
// api is the API type you want to use. For now it can be either 'rest' or 'xml'
func ShowInterface(fip, Intrfc, key, api string) ([]byte, error) {

	switch api {
	// To do: showInterfaceRST
	/*
		case "rest":
			{
				return showInterfaceRST(fip, Intrfc, key)
			}
	*/
	case "xml":
		{
			return showInterfaceXML(fip, Intrfc, key)
		}
	default:
		{
			return nil, errors.New("wrong type of API is used.")
		}
	}

	return nil, errors.New("wrong type of API is used.")

}

// showInterfaceXML generates XML URL to be used to get firewall interface information. This coresonds corresponds
// the command 'show interface <interface>' in CLI but here is used on firewall XML API.
// Output will be in XML format. In the command we have:
// fip is Firewall IP
// Intrfc is the interface we want
// key is Token/Key should be takan manually from firewall
func showInterfaceXML(fip, Intrfc, key string) ([]byte, error) {

	url := "https://" + fip + "/api/?type=op&cmd=<show><interface>" + Intrfc
	url = url + "</interface></show>&key=" + key

	method := "GET"

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	client := &http.Client{Transport: tr}

	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, errors.New("Error in http connection:" + resp.Status)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	return body, nil
}

// showInterfaceRST generates REST URL to be used to get firewall interface information. This coresonds corresponds
// the command 'show interface <interface>' in CLI but here is used on firewall REST API.
// Output will be in XML format. In the command we have:
// fip is Firewall IP
// Intrfc is the interface we want
// key is Token/Key should be takan manually from firewall
func showInterfaceRST(fip, vr, dip, key string) ([]byte, error) {
	// To Do
	//
	return nil, nil
}

// TestSecurityPolicyMatch generates REST/XML URL to be used to get firewall policy match. This coresonds corresponds
// the command 'test security-policy-match protocol 6 from <source-zone> to <destination-zone> source <source-ip-address>
// destination <destination-ip-address> destination-port <destination-port> application <application-name>
// Output will be in XML/Jason format, depends on how the parameter 'api' is used.
// fip is Firewall IP
// cfg is an 7-cell array in which we put these:
// cfg[0] is Protocol Number (e.g. 6)
// cfg[1] is Source Zone
// cfg[2] is Destination Zone
// cfg[3] is Source IP
// cfg[4] is Destination IP
// cfg[5] is Destination Port
// cfg[6] is Application
// key is Token/Key should be takan manually from firewall
// api is the API type you want to use. For now it can be either 'rest' or 'xml'
func TestSecurityPolicyMatch(fip string, cfg [7]string, key, api string) ([]byte, error) {

	switch api {
	// To do: testSecurityPolicyMatchRST
	/*
		case "rest":
			{
				return testSecurityPolicyMatchRST(fip, Intrfc, key)
			}
	*/
	case "xml":
		{
			return testSecurityPolicyMatchXML(fip, cfg, key)
		}
	default:
		{
			return nil, errors.New("wrong type of API is used.")
		}
	}

	return nil, errors.New("wrong type of API is used.")
}

// testSecurityPolicyMatchXML generates an URL to be used to get firewall interface information. This coresonds corresponds
// the command 'test security-policy-match protocol 6 from <source-zone> to <destination-zone> source <source-ip-address>
// destination <destination-ip-address> destination-port <destination-port> application <application-name>' in CLI but here is used on firewall XML API.
// Output will be in XML format
// fip is Firewall IP
// cfg is an 7-cell array in which we put these:
// cfg[0] is Protocol Number (e.g. 6)
// cfg[1] is Source Zone
// cfg[2] is Destination Zone
// cfg[3] is Source IP
// cfg[4] is Destination IP
// cfg[5] is Destination Port
// cfg[6] is Application
// key is Token/Key should be takan manually from firewall
func testSecurityPolicyMatchXML(fip string, cfg [7]string, key string) ([]byte, error) {

	if cfg[0] == "" {
		return nil, errors.New("Fist parameter should be protocol number!\n")
	}
	if cfg[1] == "" {
		return nil, errors.New("Second parameter should be Source Zone!\n")
	}
	if cfg[2] == "" {
		return nil, errors.New("Fist parameter should be Destination Zone!\n")
	}
	if cfg[3] == "" {
		return nil, errors.New("Fist parameter should be Source IP!\n")
	}
	if cfg[4] == "" {
		return nil, errors.New("Fist parameter should be Destination IP!\n")
	}
	if cfg[5] == "" {
		return nil, errors.New("Fist parameter should be Destination Port!\n")
	}

	url := "https://" + fip + "/api/?type=op&cmd="
	url = url + "<test><security-policy-match>"
	url = url + "<protocol>" + cfg[0] + "</protocol>"
	url = url + "<from>" + cfg[1] + "</from><to>" + cfg[2] + "</to>"
	url = url + "<source>" + cfg[3] + "</source><destination>" + cfg[4] + "</destination>"
	url = url + "<destination-port>" + cfg[5] + "</destination-port>"

	if cfg[6] != "nil" {
		url = url + " application "
		url = url + "<application>" + cfg[6] + "</application>"
	}

	url = url + "</security-policy-match></test>"
	url = url + "&key=" + key

	method := "GET"

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	client := &http.Client{Transport: tr}

	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, errors.New("Error in http connection:" + resp.Status)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	return body, nil
}

// testSecurityPolicyMatchRST generates REST URL to be used to get firewall interface information. This coresonds corresponds
// the command 'test security-policy-match protocol 6 from <source-zone> to <destination-zone> source <source-ip-address>
// destination <destination-ip-address> destination-port <destination-port> application <application-name>' in CLI but here is used on firewall REST API.
// Output will be in JSON format
// fip is Firewall IP
// cfg is an 7-cell array in which we put these:
// cfg[0] is Protocol Number (e.g. 6)
// cfg[1] is Source Zone
// cfg[2] is Destination Zone
// cfg[3] is Source IP
// cfg[4] is Destination IP
// cfg[5] is Destination Port
// cfg[6] is Application
// key is Token/Key should be takan manually from firewall
func testSecurityPolicyMatchRST(fip string, cfg [7]string, key string) ([]byte, error) {
	// To Do
	//
	return nil, nil
}

func FindObjectAddress() ([]byte, error) {
	// To Do
	//
	return nil, nil
}

// REST Network
// https://192.168.1.249/restapi/v9.1/Network/SDWANInterfaceProfiles
// https://192.168.1.249/restapi/v9.1/Network/EthernetInterfaces?name=ethernet1/1
// https://192.168.1.249/restapi/v9.1/Network/VirtualRouters?name=default

// REST Get Object names
// https://192.168.1.249/restapi/v9.1/Objects/Addresses?location=vsys&vsys=vsys1
// https://192.168.1.249/restapi/v9.1/Objects/Addresses?location=vsys&vsys=vsys1&name=Eth1_1.1.1.254_24
// https://192.168.1.249/restapi/v9.1/Objects/AddressGroups?location=vsys&vsys=vsys1&name=TestObject

// REST Get Firewall Policy
// https://192.168.1.249/restapi/v9.1/Policies/SecurityRules?location=vsys&vsys=vsys1&name=Z1-Z2
// https://192.168.1.249/restapi/v9.1/Policies/SecurityRules?location=vsys&vsys=vsys1&source=HOST_10.1.0.1

// Push Frewall Policy
