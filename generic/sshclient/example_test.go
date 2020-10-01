package sshclient

import (
	"fmt"
	"log"
	"time"
)

func Example_execCommandsAdvaned() {

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

	result, err := ExecCommandsAdvaned(rhc, initcmd, listCMDs, sshconfig)
	if err != nil {
		log.Fatal(err)
	}

	for _, item := range result {
		fmt.Println(item.Cmd)
		fmt.Println(item.Result)
	}

}

func Example_execCommandsSimple() {

	// List of the commands should be sent to the devices
	listCMDs := []string{
		"test routing fib-lookup virtual-router default ip 1.1.1.1",
		"show interface ethernet1/1 | match zone",
		"exit",
	}

	sshconfig := InsecureClientConfig("admin", "admin", 5*time.Second)

	rhc := CreateRhConfig("192.168.1.1", "tcp", "22")

	result, err := ExecCommandsSimple(rhc, listCMDs, sshconfig)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(result)
}
