package palapi

import (
	"fmt"
	"log"
)

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

	// Get FIB info for IP 1.1.1.1 on the Virtual Router 'default'
	b, err := c.TestRouteFibLookup("default", "1.1.1.1")
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(string(b))
}
