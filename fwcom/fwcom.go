package fwcom

import (
	"encoding/csv"
	"errors"
	"io"
	"log"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/cbt4all/mytoolkits"
)

// ReadFWRulesFile ...
func ReadFWRulesFile(fpath string) ([]FwRule, error) {

	var fwrule []FwRule

	// Open CSV file
	f, err := os.Open(fpath)
	if err != nil {
		return fwrule, err
	}
	defer f.Close()

	// Map columns/fields to column number
	scvFields := make(map[string]int)

	// Parse CSV file - return fwcom.FwRule
	csvReader := csv.NewReader(f)
	for rowCount := 0; ; rowCount++ {
		record, err := csvReader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fwrule, err
		}

		//------------ Fill the fields-column Map
		if rowCount == 0 {
			for idx, column := range record {
				scvFields[column] = idx
			}
		} else {
			//------------ Parse CSV recoreds
			fwrule = append(fwrule, ParseRecords(record, scvFields))
		}
	}
	return fwrule, nil
}

// ParseRecords ...
func ParseRecords(record []string, csvColumns map[string]int) FwRule {
	var fwrule FwRule

	// Source/Destination IPs are validate laters
	SrcIPs := strings.Split(record[csvColumns["Sources"]], "\n")
	DstIPs := strings.Split(record[csvColumns["Destinations"]], "\n")

	record[csvColumns["Protocol"]] = strings.ReplaceAll(record[csvColumns["Protocol"]], "\\", "\n")
	record[csvColumns["Protocol"]] = strings.ReplaceAll(record[csvColumns["Protocol"]], "-", "\n")
	record[csvColumns["Protocol"]] = strings.ReplaceAll(record[csvColumns["Protocol"]], ";", "\n")
	Protocol := strings.Split(record[csvColumns["Protocol"]], "\n")

	record[csvColumns["Ports"]] = strings.ReplaceAll(record[csvColumns["Ports"]], "\\", "\n")
	record[csvColumns["Ports"]] = strings.ReplaceAll(record[csvColumns["Ports"]], "-", "\n")
	record[csvColumns["Ports"]] = strings.ReplaceAll(record[csvColumns["Ports"]], ";", "\n")
	Ports := strings.Split(record[csvColumns["Ports"]], "\n")

	fwrule.SrcIPs = ValidateIPs(SrcIPs)
	fwrule.DstIPs = ValidateIPs(DstIPs)
	fwrule.Protocol = Protocol
	fwrule.Ports = Ports

	Application := record[csvColumns["Application"]]
	fwrule.Application = Application

	return fwrule
}

// ConvertFwRuleToSimple ...
func ConvertFwRuleToSimple(fwr []FwRule) []FwRuleSimple {
	var fws []FwRuleSimple

	for a := 0; a < len(fwr); a++ {
		for b := 0; b < len(fwr[a].SrcIPs); b++ {
			for c := 0; c < len(fwr[a].DstIPs); c++ {
				for d := 0; d < len(fwr[a].Protocol); d++ {
					for e := 0; e < len(fwr[a].Ports); e++ {
						fws = append(fws, FwRuleSimple{
							FwRuleIdx:   a,
							SrcIP:       fwr[a].SrcIPs[b],
							SrcZone:     "",
							SrcInt:      "",
							DstIP:       fwr[a].DstIPs[c],
							DstZone:     "",
							DstInt:      "",
							Protocol:    fwr[a].Protocol[d],
							Port:        fwr[a].Ports[e],
							Application: fwr[a].Application,
						})
					}
				}

			}
		}
	}
	return fws
}

// ConvertSimpleToFwRule ...
func ConvertSimpleToFwRule(fws []FwRuleSimple) []FwRule {

	fwrl := fws[len(fws)-1].FwRuleIdx
	fwr := make([]FwRule, fwrl)

	var sip, dip, sz, dz, p, prot []string
	var app string
	var needed bool

	for i := 0; i < fwrl; i++ {
		for _, fwsitem := range fws {
			if i == fwsitem.FwRuleIdx {
				sip = append(sip, fwsitem.SrcIP)
				dip = append(dip, fwsitem.DstIP)
				sz = append(sz, fwsitem.SrcZone)
				dz = append(dz, fwsitem.DstZone)
				p = append(p, fwsitem.Port)
				prot = append(prot, fwsitem.Protocol)
				app = fwsitem.Application
				needed = needed || fwsitem.Needed
			}
		}
		// Remove duplicate
		tsip := mytoolkits.RemoveDuplicatesFromSliceString(sip)
		tdip := mytoolkits.RemoveDuplicatesFromSliceString(dip)
		tp := mytoolkits.RemoveDuplicatesFromSliceString(p)
		tprot := mytoolkits.RemoveDuplicatesFromSliceString(prot)

		fwr[i].SrcIPs = tsip
		fwr[i].DstIPs = tdip
		fwr[i].Ports = tp
		fwr[i].Protocol = tprot
		fwr[i].Application = app
		fwr[i].Needed = needed

		sip = nil
		dip = nil
		sz = nil
		dz = nil
		p = nil
		prot = nil
		app = ""
		needed = false
	}
	return fwr
}

// ValidateIPs ...
func ValidateIPs(ips []string) []string {
	var result []string

	for _, item := range ips {
		ip := net.ParseIP(item)
		if ip != nil {
			result = append(result, ip.String())
		} else {
			log.Fatal(item + " is not a valid IP")
		}
	}
	return result
}

// WriteFwRuleSimpleCSV ...
func WriteFwRuleSimpleCSV(fpath string, fws []FwRuleSimple) error {

	// Order of the file:
	// Sources		Destinations		Protocol		Ports				Applications
	// SourceInt	DestinationsInt		SourceZone		DestinationsZone	Needed		FirewallIndex

	// Open CSV file
	f, err := os.OpenFile(fpath, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0755)
	if err != nil {
		return err
	}
	defer f.Close()

	w := csv.NewWriter(f)

	for _, fw := range fws {
		if err := w.Write([]string{
			fw.SrcIP,
			fw.DstIP,
			fw.Protocol,
			fw.Port,
			fw.Application,
			fw.SrcInt,
			fw.DstInt,
			fw.SrcZone,
			fw.DstZone,
			strconv.FormatBool(fw.Needed),
			strconv.Itoa(fw.FwRuleIdx),
		}); err != nil {

			return err
		}
	}

	// Write any buffered data to the underlying writer (standard output).
	w.Flush()

	if err := w.Error(); err != nil {
		return err
	}

	return nil
}

// WriteFwRuleCSV ...
func WriteFwRuleCSV(fpath string, fwr []FwRule) error {

	// Order of the file:
	// Sources	Destinations	Protocol	Ports	Applications	Needed

	// Creating outerr as Output Error.
	outerr := errors.New("nil")
	outerr = nil

	// Open CSV file
	f, err := os.OpenFile(fpath, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0755)
	if err != nil {
		outerr = err
		return outerr
	}
	defer f.Close()

	w := csv.NewWriter(f)

	for _, fw := range fwr {
		if err := w.Write([]string{
			strings.Join(fw.SrcIPs, " "),
			strings.Join(fw.DstIPs, " "),
			strings.Join(fw.Protocol, "\\"),
			strings.Join(fw.Ports, "\\"),
			"",
			strconv.FormatBool(fw.Needed),
		}); err != nil {
			outerr = err
			return outerr
		}
	}

	// Write any buffered data to the underlying writer (standard output).
	w.Flush()

	if err := w.Error(); err != nil {
		outerr = err
		return outerr
	}

	return outerr
}
