package parest

import (
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
)

// TestRouteFibLookupRest generates REST URL to be used to get firewall interface information. This coresonds corresponds with
// the command 'test routing fib-lookup virtual-router <virtual-router> ip <ip-address>' in CLI but here is used on firewall REST API.
// Output will be in XML format. In the command we have:
// fip is Firewall IP
// vr is Virtual-Router
// dip is Destination IP
// key is Token/Key should be takan manually from firewall
func TestRouteFibLookupRest(fip, vr, dip, key string) []byte {

	url := "https://" + fip + "/api/?type=op&cmd=<test><routing><fib-lookup><virtual-router>" + vr + "</virtual-router>"
	url = url + "<ip>" + dip + "</ip></fib-lookup></routing></test>&key=" + key

	method := "GET"

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	client := &http.Client{Transport: tr}

	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		fmt.Println(err)
	}

	resp, err := client.Do(req)
	if err != nil {
		fmt.Println(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		log.Fatal(resp.Status)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Println(err)
	}

	return body
}

// ShowInterfaceRest generates REST URL to be used to get firewall interface information. This coresonds corresponds with
// the command 'show interface <interface>' in CLI but here is used on firewall REST API.
// Output will be in XML format. In the command we have:
// fip is Firewall IP
// Intrfc is the interface we want
// key is Token/Key should be takan manually from firewall
func ShowInterfaceRest(fip, Intrfc, key string) []byte {

	url := "https://" + fip + "/api/?type=op&cmd=<show><interface>" + Intrfc
	url = url + "</interface></show>&key=" + key

	method := "GET"

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	client := &http.Client{Transport: tr}

	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		fmt.Println(err)
	}

	resp, err := client.Do(req)
	if err != nil {
		fmt.Println(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		log.Fatal(resp.Status)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Println(err)
	}

	return body
}

// TestSecurityPolicyMatch ...
func TestSecurityPolicyMatch() {

	// test security-policy-match protocol 6 from ZONE1 to ZONE9 source 10.1.1.1 destination 10.115.10.11 destination-port 135
	//<request cmd="op" cookie="4032893371262777" uid="522"><operations><test><security-policy-match><protocol>6</protocol><source>10.111.246.1</source><destination>1.1.1.1</destination><destination-port>443</destination-port><from>SYSTEMS</from><to>WAN</to></security-policy-match></test></operations></request>

}

// Get Firewall Policy

// Push Frewall Policy
