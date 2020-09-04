package passh

import "fmt"

func ExampleTestRouteFibInterfaceCmd() {
	cmd := TestRouteFibInterfaceCmd("default", "192.168.1.1")
	fmt.Println(cmd)

	// Output will be: 'test routing fib-lookup virtual-router default ip 192.168.1.1'
}

func ExampleShowInterfaceCmd() {
	inet := ShowInterfaceCmd("ae1.1345")

	fmt.Println(inet)
	// Output will be: 'show interface ae1.1345'
}

func ExampleTestSecurityPolicyMatchCmd() {

	// cfg[0] is Protocol Number (e.g. 6)
	// cfg[1] is Source Zone
	// cfg[2] is Destination Zone
	// cfg[3] is Source IP
	// cfg[4] is Destination IP
	// cfg[5] is Destination Port
	// cfg[6] is Application
	var cfg [7]string

	cfg[0] = "6"
	cfg[1] = "ZONE1"
	cfg[2] = "ZONE2"
	cfg[3] = "192.168.0.1"
	cfg[4] = "172.16.0.1"
	cfg[5] = "22"
	cfg[6] = "ssh"

	cmd, _ := TestSecurityPolicyMatchCmd(cfg)
	fmt.Println(cmd)
	// Output will be:
	// 'test security-policy-match protocol 6 from ZONE1 to ZONE2 source 192.168.0.1 destination 172.16.0.1 destination-port 22 application ssh'
}
