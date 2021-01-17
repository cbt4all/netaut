package paloalto

import "encoding/xml"

// IfNetResult is the outcome of the command 'show interface ...' in XML format
type IfNetResult struct {
	XMLName xml.Name `xml:"response"`
	Text    string   `xml:",chardata"`
	Status  string   `xml:"status,attr"`
	Result  struct {
		Text  string `xml:",chardata"`
		Ifnet struct {
			Text        string `xml:",chardata"`
			Ipv6Client  string `xml:"ipv6_client"`
			Vr          string `xml:"vr"`
			Tag         string `xml:"tag"`
			Circuitonly string `xml:"circuitonly"`
			Ndpmon      string `xml:"ndpmon"`
			ID          string `xml:"id"`
			MgtSubnet   string `xml:"mgt_subnet"`
			Addr        struct {
				Text   string `xml:",chardata"`
				Member string `xml:"member"`
			} `xml:"addr"`
			Service  string `xml:"service"`
			Gre      string `xml:"gre"`
			Ra       string `xml:"ra"`
			Zone     string `xml:"zone"`
			Counters struct {
				Text  string `xml:",chardata"`
				Ifnet struct {
					Text  string `xml:",chardata"`
					Entry struct {
						Text       string `xml:",chardata"`
						IcmpFrag   string `xml:"icmp_frag"`
						Ifwderrors string `xml:"ifwderrors"`
						Ierrors    string `xml:"ierrors"`
						Macspoof   string `xml:"macspoof"`
						Pod        string `xml:"pod"`
						Flowstate  string `xml:"flowstate"`
						Ipspoof    string `xml:"ipspoof"`
						Teardrop   string `xml:"teardrop"`
						Ibytes     string `xml:"ibytes"`
						Noarp      string `xml:"noarp"`
						SctpConn   string `xml:"sctp_conn"`
						Noroute    string `xml:"noroute"`
						Noneigh    string `xml:"noneigh"`
						Nomac      string `xml:"nomac"`
						L2Encap    string `xml:"l2_encap"`
						Zonechange string `xml:"zonechange"`
						OtherConn  string `xml:"other_conn"`
						Obytes     string `xml:"obytes"`
						Land       string `xml:"land"`
						Name       string `xml:"name"`
						TcpConn    string `xml:"tcp_conn"`
						Neighpend  string `xml:"neighpend"`
						Ipackets   string `xml:"ipackets"`
						Opackets   string `xml:"opackets"`
						L2Decap    string `xml:"l2_decap"`
						UdpConn    string `xml:"udp_conn"`
						Idrops     string `xml:"idrops"`
					} `xml:"entry"`
				} `xml:"ifnet"`
				Hw struct {
					Text  string `xml:",chardata"`
					Entry struct {
						Text     string `xml:",chardata"`
						Obytes   string `xml:"obytes"`
						Name     string `xml:"name"`
						Idrops   string `xml:"idrops"`
						Ipackets string `xml:"ipackets"`
						Opackets string `xml:"opackets"`
						Ierrors  string `xml:"ierrors"`
						Ibytes   string `xml:"ibytes"`
						Port     struct {
							Text        string `xml:",chardata"`
							TxUnicast   string `xml:"tx-unicast"`
							TxMulticast string `xml:"tx-multicast"`
							RxBroadcast string `xml:"rx-broadcast"`
							RxUnicast   string `xml:"rx-unicast"`
							RxMulticast string `xml:"rx-multicast"`
							RxBytes     string `xml:"rx-bytes"`
							TxBroadcast string `xml:"tx-broadcast"`
							TxBytes     string `xml:"tx-bytes"`
						} `xml:"port"`
					} `xml:"entry"`
				} `xml:"hw"`
			} `xml:"counters"`
			Dad      string `xml:"dad"`
			Policing string `xml:"policing"`
			Mssadjv4 string `xml:"mssadjv4"`
			Mssadjv6 string `xml:"mssadjv6"`
			Sdwan    string `xml:"sdwan"`
			FwdType  string `xml:"fwd_type"`
			Addr6    string `xml:"addr6"`
			Name     string `xml:"name"`
			Tunnel   string `xml:"tunnel"`
			Vsys     string `xml:"vsys"`
			DynAddr  string `xml:"dyn-addr"`
			Mtu      string `xml:"mtu"`
			Tcpmss   string `xml:"tcpmss"`
			Mode     string `xml:"mode"`
		} `xml:"ifnet"`
		Hw struct {
			Text    string `xml:",chardata"`
			Name    string `xml:"name"`
			Duplex  string `xml:"duplex"`
			Type    string `xml:"type"`
			StateC  string `xml:"state_c"`
			Mac     string `xml:"mac"`
			State   string `xml:"state"`
			DuplexC string `xml:"duplex_c"`
			Mode    string `xml:"mode"`
			SpeedC  string `xml:"speed_c"`
			Speed   string `xml:"speed"`
			ID      string `xml:"id"`
			Untag   string `xml:"untag"`
		} `xml:"hw"`
		Dp string `xml:"dp"`
	} `xml:"result"`
}

// FibResult is the outcome of the command 'test routing fib-lookup virtual-router ...' in XML format
type FibResult struct {
	XMLName xml.Name `xml:"response"`
	Text    string   `xml:",chardata"`
	Status  string   `xml:"status,attr"`
	Result  struct {
		Text      string `xml:",chardata"`
		Nh        string `xml:"nh"`
		Interface string `xml:"interface"`
		Dp        string `xml:"dp"`
		Src       string `xml:"src"`
	} `xml:"result"`
}

// PolicyMatchResult is the outcome of the command 'test security-policy-match ...' in XML format
type PolicyMatchResult struct {
	XMLName xml.Name `xml:"response"`
	Text    string   `xml:",chardata"`
	Cmd     string   `xml:"cmd,attr"`
	Status  string   `xml:"status,attr"`
	Result  struct {
		Text  string `xml:",chardata"`
		Rules struct {
			Text  string `xml:",chardata"`
			Entry struct {
				Text               string `xml:",chardata"`
				Name               string `xml:"name,attr"`
				Index              string `xml:"index"`
				From               string `xml:"from"`
				Source             string `xml:"source"`
				SourceRegion       string `xml:"source-region"`
				To                 string `xml:"to"`
				Destination        string `xml:"destination"`
				DestinationRegion  string `xml:"destination-region"`
				User               string `xml:"user"`
				Category           string `xml:"category"`
				ApplicationService string `xml:"application_service"`
				Action             string `xml:"action"`
				IcmpUnreachable    string `xml:"icmp-unreachable"`
				Terminal           string `xml:"terminal"`
			} `xml:"entry"`
		} `xml:"rules"`
	} `xml:"result"`
}

// ObjectsAddresses is the Object Addresses that represents Name, IP Address and Description of a Network Object.
// Example, if 'oa' be a variable of ObjectsAddresses, oa.Result.Entry[0].IPNetmask brings the IP address of the first object
type ObjectsAddresses struct {
	Status string `json:"@status"`
	Code   string `json:"@code"`
	Result struct {
		TotalCount string `json:"@total-count"`
		Count      string `json:"@count"`
		Entry      []struct {
			Name        string `json:"@name"`
			Location    string `json:"@location"`
			Vsys        string `json:"@vsys"`
			IPNetmask   string `json:"ip-netmask"`
			Description string `json:"description,omitempty"`
		} `json:"entry"`
	} `json:"result"`
}

// ObjAddEntry is Objects Addresses Entry
type ObjAddEntry struct {
	Name        string
	Location    string
	Vsys        string
	IPNetmask   string
	Description string
}

// ObjectGroupAddresses is the Object Address Groups that includes one or more Object Addresses Name.
// Example, if 'oga' be a variable of ObjectGroupAddresses, oga.Result.Entry[0].Static.Member[0] brings Object Addresses Name of the first object
type ObjectGroupAddresses struct {
	Status string `json:"@status"`
	Code   string `json:"@code"`
	Result struct {
		TotalCount string `json:"@total-count"`
		Count      string `json:"@count"`
		Entry      []struct {
			Name     string `json:"@name"`
			Location string `json:"@location"`
			Vsys     string `json:"@vsys"`
			Static   struct {
				Member []string `json:"member"`
			} `json:"static,omitempty"`
			Dynamic struct {
				Filter string `json:"filter"`
			} `json:"dynamic,omitempty"`
		} `json:"entry"`
	} `json:"result"`
}

// ObjGrpAddEntry is Object Group Addresses Entry
type ObjGrpAddEntry struct {
	Name     string
	Location string
	Vsys     string
	Static   struct{ Member []string }
	Dynamic  struct{ Filter string }
}

// SecurityRules represents Security Rules of the firewall that shows frewall Policies
type SecurityRules struct {
	Status string `json:"@status"`
	Code   string `json:"@code"`
	Result struct {
		TotalCount string `json:"@total-count"`
		Count      string `json:"@count"`
		Entry      []struct {
			Name     string `json:"@name"`
			UUID     string `json:"@uuid"`
			Location string `json:"@location"`
			Vsys     string `json:"@vsys"`
			To       struct {
				Member []string `json:"member"`
			} `json:"to"`
			From struct {
				Member []string `json:"member"`
			} `json:"from"`
			Source struct {
				Member []string `json:"member"`
			} `json:"source"`
			Destination struct {
				Member []string `json:"member"`
			} `json:"destination"`
			SourceUser struct {
				Member []string `json:"member"`
			} `json:"source-user"`
			Category struct {
				Member []string `json:"member"`
			} `json:"category"`
			Application struct {
				Member []string `json:"member"`
			} `json:"application"`
			Service struct {
				Member []string `json:"member"`
			} `json:"service"`
			HipProfiles struct {
				Member []string `json:"member"`
			} `json:"hip-profiles"`
			Action   string `json:"action"`
			LogStart string `json:"log-start"`
		} `json:"entry"`
	} `json:"result"`
}

// SecRulesEntry Security Rules Entry
type SecRulesEntry struct {
	Name        string
	UUID        string
	Location    string
	Vsys        string
	To          []string
	From        []string
	Source      []string
	Destination []string
	SourceUser  []string
	Category    []string
	Application []string
	Service     []string
	HipProfiles []string
	Action      string
	LogStart    string
}
