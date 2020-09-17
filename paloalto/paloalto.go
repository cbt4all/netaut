package paloalto

import (
	"encoding/xml"
)

// ParseXMLFibResult gets s as XML format, parses it and return a FibResult
func ParseXMLFibResult(s string) (FibResult, error) {
	// s is the string format of an xml
	var fbr FibResult

	b := []byte(s)
	err := xml.Unmarshal(b, &fbr)

	return fbr, err
}

// ParseXMLIfNet gets s as XML format, parses it and return an IfNetResult
func ParseXMLIfNet(s string) (IfNetResult, error) {
	// s is the string format of an xml
	var ifnet IfNetResult

	b := []byte(s)
	err := xml.Unmarshal(b, &ifnet)

	return ifnet, err
}

// ParseXMLPolicyMatch gets s as XML format, parses it and return a PolicyMatchResult
func ParseXMLPolicyMatch(s string) (PolicyMatchResult, error) {
	// s is the string format of an xml
	var plcm PolicyMatchResult

	b := []byte(s)
	err := xml.Unmarshal(b, &plcm)

	return plcm, err
}
