package palapi

import (
	"fmt"
	"log"
)

func ExampleNewClientSettings() {

	cs, err := NewClientSettings(1, 1, "", "admin", "admin")
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(cs.Username)
}
