package parest

import (
	"crypto/tls"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
)

// TestRouteFibLookupRest generates REST URL to be used to get firewall interface information. This coresonds corresponds
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

// ShowInterfaceRest generates REST URL to be used to get firewall interface information. This coresonds corresponds
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

// TestSecurityPolicyMatchRest generates REST URL to be used to get firewall interface information. This coresonds corresponds
// the command 'test security-policy-match protocol 6 from <source-zone> to <destination-zone> source <source-ip-address>
// destination <destination-ip-address> destination-port <destination-port> application <application-name>
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
func TestSecurityPolicyMatchRest(fip string, cfg [7]string, key string) ([]byte, error) {

	//<test><security-policy-match>
	//<protocol>6</protocol>
	//<from>ZONE1</from><to>ZONE2</to>
	//<source>10.111.246.1</source><destination>1.1.1.1</destination>
	//<destination-port>22</destination-port>
	//<application>ssh</application>
	//</security-policy-match></test>

	outErr := errors.New("nil")
	outErr = nil
	var result string

	if cfg[0] == "" {
		outErr = errors.New("Fist parameter should be protocol number!\n")
		return []byte(""), outErr
	}
	if cfg[1] == "" {
		outErr = errors.New("Second parameter should be Source Zone!\n")
		return []byte(""), outErr
	}
	if cfg[2] == "" {
		outErr = errors.New("Fist parameter should be Destination Zone!\n")
		return []byte(""), outErr
	}
	if cfg[3] == "" {
		outErr = errors.New("Fist parameter should be Source IP!\n")
		return []byte(""), outErr
	}
	if cfg[4] == "" {
		outErr = errors.New("Fist parameter should be Destination IP!\n")
		return []byte(""), outErr
	}
	if cfg[5] == "" {
		outErr = errors.New("Fist parameter should be Destination Port!\n")
		return []byte(""), outErr
	}

	url := "https://" + fip + "/api/?type=op&cmd="
	url = url + "<test><security-policy-match>"
	url = url + "<protocol>" + cfg[0] + "</protocol>"
	url = url + "<from>" + cfg[1] + "</from><to>" + cfg[2] + "</to>"
	url = url + "<source>" + cfg[3] + "</source><destination>" + cfg[4] + "</destination>"
	url = url + "<destination-port>" + cfg[5] + "</destination-port>"

	if cfg[6] != "nil" {
		result = result + " application "
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

	return body, outErr

}

// Get Firewall Policy

// Push Frewall Policy
