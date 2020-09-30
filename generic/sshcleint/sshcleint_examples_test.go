package sshcleint

func ExampleNewTClient() {

	sshconfig := InsecureClientConfig("admin", "admin")

	tc, err := NewTClient("192.168.1.1", sshconfig)

	//fmt.Println(cmd)

	// Output:
	// test routing fib-lookup virtual-router default ip 192.168.1.1
}
