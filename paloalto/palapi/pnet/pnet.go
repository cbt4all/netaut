package pnet

import (
	"crypto/tls"
	"errors"
	"io/ioutil"
	"net/http"
)

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
func (c PClient) TestRouteFibLookup(vr, dip string) ([]byte, error) {

	switch c.Settings.Api {
	// To do: testRouteFibLookupRST
	/*
		case "rest":
			{
				return testRouteFibLookupRST(fip, vr, dip, key)
			}
	*/
	case "xml":
		{
			return c.testRouteFibLookupXML(vr, dip)
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
func (c PClient) testRouteFibLookupXML(vr, dip string) ([]byte, error) {

	url := "https://" + c.Fip + "/api/?type=op&cmd=<test><routing><fib-lookup><virtual-router>" + vr + "</virtual-router>"
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
