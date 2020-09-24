package palapi

import (
	"fmt"
	"log"
)

func ExampleshowInterface() {

	cs, err := NewClientSettings(1, 1, "", "admin", "admin")
	if err != nil {
		log.Fatal(err)
	}

	c, err := NewPClient(cs, "192.168.1.249", "", true)
	if err != nil {
		log.Fatal(err)
	}

	b, err := c.TestRouteFibLookup("default", "1.1.1.1")
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(string(b))
}

func ExampleNewClientSettings() {

	cs, err := NewClientSettings(1, 1, "", "admin", "admin")
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(cs.Username)
}
