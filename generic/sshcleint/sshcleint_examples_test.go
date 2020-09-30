package sshcleint

import (
	"fmt"
	"log"
)

func ExampleNewTClient() {

	sshconfig := InsecureClientConfig("admin", "admin")

	tc, err := NewTClient("192.168.1.1", sshconfig)
	if err != nil {
		log.Fatal(err)
	}

	initcmd := []string{
		"set cli op-command-xml-output on\n",
	}

	// List of the commands should be sent to the devices
	listCMDs := []string{
		"test routing fib-lookup virtual-router default ip 1.1.1.1\n",
		"test routing fib-lookup virtual-router default ip 2.2.2.2\n",
		"exit",
	}

	restult, err := tc.ExecCmds(initcmd, listCMDs)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(restult)
	// Output:
	// test routing fib-lookup virtual-router default ip 192.168.1.1
}
