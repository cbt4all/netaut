package palapi

import (
	"fmt"
	"log"

	"github.com/cbt4all/netaut/paloalto/palapi"
)

func ExamplePClient_GetInterfaceFromFIB() {

	// Create a new ClientSettings using Username/Password
	cs, err := NewClientSettings(1, 1, "", "admin", "password")
	if err != nil {
		log.Fatal(err)
	}

	// Create a new Palo Alto Client
	c, err := NewPClient(cs, "192.168.1.249", "", true)
	if err != nil {
		log.Fatal(err)
	}

	// Get FIB info for IP 1.1.1.1 on the Virtual Router 'default'
	b, err := c.GetInterfaceFromFIB("default", "1.1.1.1")
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(string(b))
	// Output:
	// ethernet1/1
}

func ExamplePClient_TestRouteFibLookup() {

	// This example uses Key to login to Palo Alto
	// Use this link to find how to get the Key: https://docs.paloaltonetworks.com/content/techdocs/en_US/pan-os/9-0/pan-os-panorama-api.html
	key := "LUFRPT1GdWNLZzdXM2svZ1JZTVNreXdGRU1xRktrNnc9T3RxUGZDVkQrNDNVdXV1K3F3L2gvTWZZNFdqdXNIQjlkUDBTSWtWazl6anhLQmVZT3lzaUdCVWEvRGs1UTQydA=="

	// Create a new ClientSettings Using Token/Key
	cs, err := NewClientSettings(1, 0, key, "", "")
	if err != nil {
		log.Fatal(err)
	}

	// Create a new Palo Alto Client
	c, err := NewPClient(cs, "192.168.1.249", "", true)
	if err != nil {
		log.Fatal(err)
	}

	// Get FIB info for IP 1.1.1.1 on the Virtual Router 'default'
	b, err := c.TestRouteFibLookup("default", "1.1.1.1")
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(string(b))
	// Output:
	//
	//<response status="success"><result>
	//	<nh>ip</nh>
	//	<interface>ethernet1/1</interface>
	//	<dp>dp0</dp>
	//	<src>1.1.1.253</src>
	//<result></response>
}

func ExamplePClient_GetZoneFromInt() {

	// Create a new ClientSettings using Username/Password
	cs, err := NewClientSettings(1, 1, "", "admin", "password")
	if err != nil {
		log.Fatal(err)
	}

	// Create a new Palo Alto Client
	c, err := NewPClient(cs, "192.168.1.249", "", true)
	if err != nil {
		log.Fatal(err)
	}

	// Get information of the interface ethernet1/1
	b, err := c.GetZoneFromInt("ethernet1/1")
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(string(b))
	// Output:
	// ZONE1
}

func ExamplePClient_ShowInterface() {

	// Create a new ClientSettings using Username/Password
	cs, err := NewClientSettings(1, 1, "", "admin", "password")
	if err != nil {
		log.Fatal(err)
	}

	// Create a new Palo Alto Client
	c, err := NewPClient(cs, "192.168.1.249", "", true)
	if err != nil {
		log.Fatal(err)
	}

	// Get information of the interface ethernet1/1
	b, err := c.ShowInterface("ethernet1/1")
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(string(b))
}

func ExamplePClient_GetPolicyMatch() {

	// Create a new ClientSettings using Username/Password
	cs, err := NewClientSettings(1, 1, "", "admin", "password")
	if err != nil {
		log.Fatal(err)
	}

	// Create a new Palo Alto Client
	c, err := NewPClient(cs, "192.168.1.249", "", true)
	if err != nil {
		log.Fatal(err)
	}

	var cfg [7]string
	cfg[0] = "6"
	cfg[1] = "ZONE1"
	cfg[2] = "ZONE2"
	cfg[3] = "192.168.0.1"
	cfg[4] = "172.16.0.1"
	cfg[5] = "22"
	cfg[6] = "ssh"

	// Get Action
	b, err := c.GetPolicyMatch(cfg)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(string(b))
	// Output:
	// "deny"
}

func ExamplePClient_TestSecurityPolicyMatch() {

	// Create a new ClientSettings using Username/Password
	cs, err := NewClientSettings(1, 1, "", "admin", "password")
	if err != nil {
		log.Fatal(err)
	}

	// Create a new Palo Alto Client
	c, err := NewPClient(cs, "192.168.1.249", "", true)
	if err != nil {
		log.Fatal(err)
	}

	var cfg [7]string
	cfg[0] = "6"
	cfg[1] = "ZONE1"
	cfg[2] = "ZONE2"
	cfg[3] = "192.168.0.1"
	cfg[4] = "172.16.0.1"
	cfg[5] = "22"
	cfg[6] = "ssh"

	// Get the result of Test Security Policy Match
	b, err := c.TestSecurityPolicyMatch(cfg)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(string(b))

	// Output:
	//<response cmd="status" status="success">
	//	<result>
	//		<rules>
	//			<entry name="DenyAll">
	//				<index>9</index>
	//				<from>any</from>
	//				<source>any</source>
	//				<source-region>none</source-region>
	//				<to>any</to>
	//				<destination>any</destination>
	//				<destination-region>none</destination-region>
	//				<user>any</user>
	//				<category>any</category>
	//				<application_service>0:any/any/any/app-default</application_service>
	//				<action>deny</action>
	//				<icmp-unreachable>no</icmp-unreachable>
	//				<terminal>no</terminal>
	//			</entry>
	//		</rules>
	//	</result>
	//</response>
}

func ExamplePClient_FindObjAdd() {

	// Create a new ClientSettings using Username/Password
	cs, err := palapi.NewClientSettings(0, 1, "", "admin", "password")
	if err != nil {
		log.Fatal(err)
	}

	// Create a new Palo Alto Client
	c, err := palapi.NewPClient(cs, "192.168.1.251", "", true)
	if err != nil {
		log.Fatal(err)
	}

	// Get all firewall Objects Addresses
	oa1, err := c.FindObjAdd(c.Fip, "", "")
	if err != nil {
		log.Fatal(err)
	}

	// Check if the 10.0.1.3/32 exist in the found Objects Addresses.
	// Use this method when Objects Addresses Name is not known
	for idx, item := range oa1 {
		if item.IPNetmask == "10.0.1.3/32" {
			fmt.Println(idx, item.IPNetmask, item.Name)
		}
	}

	// Find a firewall Objects Addresses with the name HOST_10.0.1.3 as an Objects Addresses in the Virtual System vsys2
	// Use this method when Objects Addresses Name known
	oa2, err := c.FindObjAdd(c.Fip, "HOST_10.0.1.3", "vsys2")
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(oa2[0].IPNetmask, oa2[0].Name)

	// Output:
	// 7 10.0.1.3/32 HOST_10.0.1.3
	// 10.0.1.3/32 HOST_10.0.1.3
}
