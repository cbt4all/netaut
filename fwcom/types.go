package fwcom

// FwRule ...
type FwRule struct {
	SrcIPs   []string
	SrcZone  []string
	DstIPs   []string
	DstZone  []string
	Protocol []string
	Ports    []string
	Needed   bool
}

// FwRuleSimple ...
type FwRuleSimple struct {

	// If the Type FwRule is used, FwRuleIdx is the index of FwRule
	FwRuleIdx int
	SrcIPs    string
	SrcZone   string
	SrcInt    string

	DstIPs  string
	DstZone string
	DstInt  string

	Protocol string
	Ports    string
	Needed   bool
}
