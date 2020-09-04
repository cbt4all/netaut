package passh

import "fmt"

func ExampleTestRouteFibInterfaceCmd() {
	cmd := TestRouteFibInterfaceCmd("default", "192.168.1.1")
	fmt.Println(cmd)

	//Output will be: test routing fib-lookup virtual-router default ip 192.168.1.1
}
