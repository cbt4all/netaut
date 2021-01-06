package paloalto

import (
	"encoding/json"
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

// ParseJsonObjAdd gets s as JSON format, parses it and return an ObjectsAddresses
func ParseJsonObjAdd(s string) (ObjectsAddresses, error) {
	// s is the string format of an Json
	var oa ObjectsAddresses

	b := []byte(s)
	err := json.Unmarshal(b, &oa)

	return oa, err
}

// ParseJsonObjAddGrp gets s as JSON format, parses it and return an ObjectGroupAddresses
func ParseJsonObjAddGrp(s string) (ObjectGroupAddresses, error) {
	// s is the string format of an Json
	var oga ObjectGroupAddresses

	b := []byte(s)
	err := json.Unmarshal(b, &oga)

	return oga, err
}
