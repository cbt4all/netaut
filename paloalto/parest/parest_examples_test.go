package parest

import "fmt"

func ExampleTestRouteFibLookupRest() {

	b := TestRouteFibLookupRest("192.168.1.250", "default", "172.1.16.1", "LUFRPT14MW5xOEo1R09KVlBZNnpnemh0")
	fmt.Println(string(b))

	// What is sent is:
	// https://192.168.1.250/api/?type=op&cmd=<test><routing><fib-lookup><virtual-router>default</virtual-router>
	// <ip>172.1.16.1</ip></fib-lookup></routing></test>&key=LUFRPT14MW5xOEo1R09KVlBZNnpnemh0

	// Output:
	// <response status="success">
	// <result>
	// <nh>ip</nh>
	// <src>9.9.9.254</src>
	// <ip>9.9.9.9</ip>
	// <metric>10</metric>
	// <interface>ethernet1/9</interface>
	// <dp>dp0</dp>
	// </result>
	// </response>
}

func ExampleShowInterfaceRest() {

	b := ShowInterfaceRest("192.168.1.250", "ethernet1/1", "LUFRPT14MW5xOEo1R09KVlBZNnpnemh0")
	fmt.Println(string(b))

	// What is sent:
	// https://192.168.1.250/api/?type=op&cmd=<show><interface>ethernet1/1</interface></show>
	// &key=LUFRPT14MW5xOEo1R09KVlBZNnpnemh0

	// Output:
	/*
		response status="success">
			<result>
				<ifnet>
					<ipv6_client>False</ipv6_client>
					<vr>default</vr>
					<tag>0</tag>
					<circuitonly>False</circuitonly>
					<ndpmon>False</ndpmon>
					<id>16</id>
					<mgt_subnet>False</mgt_subnet>
					<addr>
						<member>1.1.1.254/24</member>
					</addr>
					<service/>
					<gre>False</gre>
					<ra>False</ra>
					<zone>ZONE1</zone>
					<counters>
						<ifnet>
							<entry>
								<icmp_frag>0</icmp_frag>
								<ifwderrors>0</ifwderrors>
								<ierrors>0</ierrors>
								<macspoof>0</macspoof>
								<pod>0</pod>
								<flowstate>0</flowstate>
								<ipspoof>0</ipspoof>
								<teardrop>0</teardrop>
								<ibytes>0</ibytes>
								<noarp>0</noarp>
								<sctp_conn>0</sctp_conn>
								<noroute>0</noroute>
								<noneigh>0</noneigh>
								<nomac>0</nomac>
								<l2_encap>0</l2_encap>
								<zonechange>0</zonechange>
								<other_conn>0</other_conn>
								<obytes>0</obytes>
								<land>0</land>
								<name>ethernet1/1</name>
								<tcp_conn>0</tcp_conn>
								<neighpend>0</neighpend>
								<ipackets>0</ipackets>
								<opackets>0</opackets>
								<l2_decap>0</l2_decap>
								<udp_conn>0</udp_conn>
								<idrops>0</idrops>
							</entry>
						</ifnet>
						<hw>
							<entry>
							<obytes>0</obytes>
							<name>ethernet1/1</name>
							<idrops>0</idrops>
							<ipackets>0</ipackets>
							<opackets>0</opackets>
							<ierrors>0</ierrors>
							<ibytes>0</ibytes>
								<port>
									<tx-unicast>0</tx-unicast>
									<tx-multicast>0</tx-multicast>
									<rx-broadcast>0</rx-broadcast>
									<rx-unicast>0</rx-unicast>
									<rx-multicast>0</rx-multicast>
									<rx-bytes>0</rx-bytes>
									<tx-broadcast>0</tx-broadcast>
									<tx-bytes>0</tx-bytes>
								</port>
							</entry>
						</hw>
					</counters>
					<dad>False</dad>
					<policing>False</policing>
					<mssadjv4>0</mssadjv4>
					<mssadjv6>0</mssadjv6>
					<sdwan>False</sdwan>
					<fwd_type>vr</fwd_type>
					<addr6/>
					<name>ethernet1/1</name>
					<tunnel/>
					<vsys>vsys1</vsys>
					<dyn-addr/>
					<mtu>1500</mtu>
					<tcpmss>False</tcpmss>
					<mode>layer3</mode>
				</ifnet>
				<hw>
					<name>ethernet1/1</name>
					<duplex>auto</duplex>
					<type>0</type>
					<state_c>auto</state_c>
					<mac>0c:8a:bc:48:a7:01</mac>
					<state>up</state>
					<duplex_c>auto</duplex_c>
					<mode>layer3</mode>
					<speed_c>auto</speed_c>
					<speed>auto</speed>
					<id>16</id>
					<untag>False</untag>
				</hw>
				<dp>dp0</dp>
			</result>
		</response>
	*/
}

ExampleTestSecurityPolicyMatchRest(){
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

	b, _ := TestSecurityPolicyMatchRest("192.168.1.250",cfg,"LUFRPT14MW5xOEo1R09KVlBZNnpnemh0")
	fmt.Println(string(b))

	// Output:
	// test security-policy-match protocol 6 from ZONE1 to ZONE2 source 192.168.0.1 destination 172.16.0.1 destination-port 22 application ssh
}
