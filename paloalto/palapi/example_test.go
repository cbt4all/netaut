package palapi

import (
	"fmt"
	"log"
)

func Example_GetInterfaceFromFIB() {

	// Create a new ClientSettings
	cs, err := NewClientSettings(1, 1, "", "admin", "admin")
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

func Example_testRouteFibLookup() {

	// Create a new ClientSettings
	cs, err := NewClientSettings(1, 1, "", "admin", "admin")
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
}

func Example_getZoneFromInt() {

	// Create a new ClientSettings
	cs, err := NewClientSettings(1, 1, "", "admin", "admin")
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

func Example_showInterface() {

	// Create a new ClientSettings
	cs, err := NewClientSettings(1, 1, "", "admin", "admin")
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

func Example_testSecurityPolicyMatch() {

	// Create a new ClientSettings
	cs, err := NewClientSettings(1, 1, "", "admin", "admin")
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
	/*
		<response cmd="status" status="success">
			<result>
				<rules>
					<entry name="DenyAll">
						<index>9</index>
						<from>any</from>
						<source>any</source>
						<source-region>none</source-region>
						<to>any</to>
						<destination>any</destination>
						<destination-region>none</destination-region>
						<user>any</user>
						<category>any</category>
						<application_service>0:any/any/any/app-default</application_service>
						<action>deny</action>
						<icmp-unreachable>no</icmp-unreachable>
						<terminal>no</terminal>
					</entry>
				</rules>
			</result>
		</response>
	*/
}
