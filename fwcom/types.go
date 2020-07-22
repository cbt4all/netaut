package fwcom

// FwRule ...
type FwRule struct {
	SrcIPs   []string
	DstIPs   []string
	Protocol []string
	Ports    []string
	Needed   bool
}

// FwRuleSimple ...
type FwRuleSimple struct {

	// If the Type FwRule is used, FwRuleIdx is the index of FwRule
	FwRuleIdx int
	SrcIP     string
	SrcZone   string
	SrcInt    string

	DstIP   string
	DstZone string
	DstInt  string

	Protocol string
	Port     string
	Needed   bool
}
