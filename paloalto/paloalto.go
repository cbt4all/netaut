package paloalto

import (
	"encoding/xml"
	"errors"
)

// ParseXMLFibResult ...
func ParseXMLFibResult(s string) (FibResult, error) {

	// s is the string format of an xml

	var fbr FibResult

	// Creating outerr as Output Error.
	outerr := errors.New("nil")
	outerr = nil

	b := []byte(s)
	outerr = xml.Unmarshal(b, &fbr)

	return fbr, outerr
}

// ParseXMLIfNet ...
func ParseXMLIfNet(s string) (IfNetResult, error) {

	// s is the string format of an xml

	var ifnet IfNetResult

	// Creating outerr as Output Error.
	outerr := errors.New("nil")
	outerr = nil

	b := []byte(s)
	outerr = xml.Unmarshal(b, &ifnet)

	return ifnet, outerr
}

// ParseXMLPolicyMatch ...
func ParseXMLPolicyMatch(s string) (PolicyMatchResult, error) {
	// s is the string format of an xml

	var plcm PolicyMatchResult

	// Creating outerr as Output Error.
	outerr := errors.New("nil")
	outerr = nil

	b := []byte(s)
	outerr = xml.Unmarshal(b, &plcm)

	return plcm, outerr
}
