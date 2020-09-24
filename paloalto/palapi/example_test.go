package palapi

import (
	"fmt"
	"log"
)

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
}
