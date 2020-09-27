package fwcom

// FwRule ...
type FwRule struct {
	SrcIPs      []string
	DstIPs      []string
	Protocol    []string // TCP/UDP
	Ports       []string
	Application string
	Needed      bool // If firewall rule is needed
}

// FwRuleSimple ...
type FwRuleSimple struct {

	// If the Type FwRule is used, FwRuleIdx is the index of FwRule
	FwRuleIdx int
	SrcIP     string // Srouce IP
	SrcZone   string // Source Zone
	SrcInt    string // Source Interface

	DstIP   string // Destination IP
	DstZone string // Destination Zone
	DstInt  string // Destination Interface

	Protocol    string // TCP/UDP
	Port        string
	Application string
	Needed      bool // If firewall rule is needed
}
