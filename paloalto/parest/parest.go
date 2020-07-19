package parest

import (
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
)

// GetFibInterface ...
func GetFibInterface(fip, vr, dip, key string) []byte {

	// https://192.168.1.250/api/?type=op&cmd=<test><routing><fib-lookup><virtual-router>default</virtual-router>
	// <ip>172.1.16.1</ip></fib-lookup></routing></test>&key=LUFRPT14MW5xOEo1R09KVlBZNnpnemh0VHRBOWl6TGM9bXcwM3JHUGVhRlNiY0dCR0srNERUQT09"

	// fip Firewall IP
	// vr Virtual-Router
	// dip Destination IP
	// key Token/Key should be takan manually

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

//GetZone ...
func GetZone(fip, Intrfc, key string) []byte {
	// <show><interface>ethernet1/1</interface></show>
	// &key=LUFRPT14MW5xOEo1R09KVlBZNnpnemh0VHRBOWl6TGM9bXcwM3JHUGVhRlNiY0dCR0srNERUQT09

	// fip Firewall IP
	// Intrfc is the Interface you need to find the Zone of
	// key Token/Key should be takan manually

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

}

// Get Firewall Policy

// Push Frewall Policy
