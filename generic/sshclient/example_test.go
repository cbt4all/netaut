package sshclient

import (
	"fmt"
	"log"
	"time"
)

func Example_execCommands() {

	// List of initial commands that dont need any outputs
	initcmd := []string{
		"set cli op-command-xml-output on",
	}

	// List of the commands should be sent to the devices
	listCMDs := []string{
		"test routing fib-lookup virtual-router default ip 1.1.1.1",
		"show interface ethernet1/1 | match zone",
		"exit",
	}

	sshconfig := InsecureClientConfig("admin", "admin", 5*time.Second)

	rhc := CreateRhConfig("192.168.1.1", "tcp", "22")

	restult, err := ExecCommands(rhc, initcmd, listCMDs, sshconfig)
	if err != nil {
		log.Fatal(err)
	}

	for _, item := range restult {
		fmt.Println(item.Cmd)
		fmt.Println(item.Result)
	}

}
