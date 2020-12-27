package palapi

import (
	"crypto/tls"
	"errors"
	"io/ioutil"
	"net"
	"net/http"

	"github.com/cbt4all/netaut/paloalto"
)

const (
	httpsPort = "443"
)

// ClientSettings represents all settings required to create a Palo Alto Client (PClient).
type ClientSettings struct {
	Auth     int    // Authentication method (0 means Key/Token and 1 = User/Pass)
	Api      int    // The API should be used (0 means REST API and 1 means XML API)
	Key      string // key is Token/Key should be takan manually from firewall
	Username string // If not using Token/Key to login to firewall need to use username and password
	Password string // If not using Token/Key to login to firewall need to use username and password
}

/*
NewClientSettings takes all parameters needed and returns a new ClientSettings.

This method gets:
	api:  The API should be used (0 means REST API and 1 means XML API)
	auth: Authentication method (0 means Key/Token and 1 = User/Pass)
	key:  Token/Key should be takan manually from firewall
	user: If not using Token/Key to login to firewall need to use username and password
	pass: If not using Token/Key to login to firewall need to use username and password
*/
func NewClientSettings(api, auth int, key, user, pass string) (*ClientSettings, error) {

	// Create a new ClientSettings
	cs := new(ClientSettings)

	// Which API should be used
	cs.Api = api

	// Choose which authentication method should be used
	cs.Auth = auth
	switch auth {
	case 0: // Using Key/Token
		{
			if key == "" {
				return nil, errors.New("Key is selected to ues but not entered.")
			}
			cs.Key = key
		}

	case 1: // Using Basic User/Pass
		{
			if user == "" || pass == "" {
				return nil, errors.New("User/Pass is selected to ues but not entered.")
			}
			cs.Username = user
			cs.Password = pass
		}
	}

	return cs, nil
}

// PClient represents a Palo Alto Client
type PClient struct {

	// ClientSettings helps us to add settings on some function we are using.
	Settings *ClientSettings

	// Fip is Firewall IP Address that the PClient should connect to
	Fip string

	// If custome port should be used while connecting to firewall
	Port string

	// Since HTTPS is used, sometimes the certificate is not intalled on the computer the program is run on. So if SkipCertVerify is 'true', it means
	// TLSClientConfig in http.Transport will use &tls.Config{InsecureSkipVerify: true}
	SkipCertVerify bool
}

/*
NewPClient takes all parameters needed and returns a new PClient

This method gets:
	cs:       A ClientSettings
	fip:      Firewall IP Address
	p:        TCP Port is used to login to the firewall. By default is 443
	certSkip: Means HTTPs certificate verfication be skipped or not. If true, means HTTPs certificate verfication be skipped
*/
func NewPClient(cs *ClientSettings, fip, p string, certSkip bool) (*PClient, error) {

	c := new(PClient)

	c.Settings = cs

	// fip is Firewall IP Address that the PClient should connect to
	if net.ParseIP(fip) == nil {
		return nil, errors.New("Entered Fip, " + fip + " is not a valid IP.")
	}
	c.Fip = fip

	// p is the TCP port number. Default is 443
	if p == "" {
		c.Port = httpsPort
	}
	c.Port = p

	// certSkip means HTTPs certificate verfication be skipped or not
	c.SkipCertVerify = certSkip

	return c, nil
}

/*
Dial gets URL and the Method used for an HTTP request, then send the request to the server and returns the result
The Method can be GET, POST, etc. that are used for HTTP requests

This method gets:
	url:  The URL that HTTP request is sent to
	mthd: The Method that HTTP request is used. Example: GET, POST, etc.
*/
func (c PClient) Dial(url, mthd string) ([]byte, error) {

	method := mthd

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: c.SkipCertVerify},
	}

	client := &http.Client{Transport: tr}

	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		return nil, err
	}

	// Using Basic User/Pass
	if c.Settings.Auth == 1 {
		req.SetBasicAuth(c.Settings.Username, c.Settings.Password)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, errors.New("Error in http connection:" + resp.Status)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	return body, nil
}

/*
TestRouteFibLookup gets FIB information for a particular IP on a specific virtual-router. It uses different protocols (REST/XML API) and authentication methods
(Key/Token or Basic User/Pass) based on what is set for PClient settings. Output will be in XML/Jason format, depends on the protocol is used. At the moment only XML API us supported by Palo Alto.

This method gets:
	vr is Virtual-Router
	ip is the IP Address
*/
func (c PClient) TestRouteFibLookup(vr, ip string) ([]byte, error) {

	switch c.Settings.Api {
	// To do: testRouteFibLookupRST
	/*
		case 0: // REST API
			{
				return ............
			}
	*/
	case 1: // XML API
		{
			url, err := c.testRouteFibLookupXML(vr, ip)
			if err != nil {
				return nil, err
			}

			b, err := c.Dial(url, "GET")
			if err != nil {
				return nil, err
			}

			return b, nil
		}
	default:
		{
			return nil, errors.New("Wrong type of API is used.")
		}
	}
}

/*
GetInterfaceFromFIB uses TestRouteFibLookup to get FIB info, then parses the XML or Jason (depends on what API is used) response to get only Interface Name field of that.

This method gets:
	vr is Virtual-Router
	ip is the IP Address
*/
func (c PClient) GetInterfaceFromFIB(vr, ip string) (string, error) {

	// Get FIB info for the IP
	result, err := c.TestRouteFibLookup(vr, ip)
	if err != nil {
		return "", err
	}

	// Parse the output
	switch c.Settings.Api {
	// To do:
	/*
		case 0: // REST API
			{
				return .....
			}
	*/
	case 1: // XML API
		{
			fbr, err := paloalto.ParseXMLFibResult(string(result))
			if err != nil {
				return "", err
			}

			return fbr.Result.Interface, nil
		}
	default:
		{
			return "", errors.New("Wrong type of API is used.")
		}
	}

}

/*
testRouteFibLookupXML generates an URL to get firewall FIB information using Palo Alto XML API. This corresponds the command
'test routing fib-lookup virtual-router <virtual-router> ip <ip-address>' in CLI. Output will be in XML format.

This method gets:
	vr is Virtual-Router
	ip is the IP Address
*/
func (c PClient) testRouteFibLookupXML(vr, ip string) (url string, err error) {

	url = "https://" + c.Fip + "/api/?type=op&cmd=<test><routing><fib-lookup><virtual-router>" + vr + "</virtual-router>"
	url = url + "<ip>" + ip + "</ip></fib-lookup></routing></test>"

	switch c.Settings.Auth {
	case 0: // Using Key/Token
		{
			url += "&key=" + c.Settings.Key
			return url, nil
		}
	case 1: // Using Basic User/Pass
		{
			return url, nil
		}
	default:
		{
			return "", errors.New("Wrong type of athentication method is used.")
		}
	}
}

/*
testRouteFibLookupRST generates an URL to get firewall FIB information using Palo Alto REST API. This corresponds the command
'test routing fib-lookup virtual-router <virtual-router> ip <ip-address>' in CLI. Output will be in JSON format.

This method gets:
	vr is Virtual-Router
	ip is the IP Address
*/
func (c PClient) testRouteFibLookupRST(vr, ip string) (url string, err error) {
	// To Do
	// https://192.168.1.249/restapi/v9.1/Network/VirtualRouters
	return "", nil
}

/*
ShowInterface gets firewall interface information for a given interface. It uses different protocols (REST/XML API) and authentication methods
(Key/Token or Basic User/Pass) based on what is set for PClient settings. Output will be in XML/Jason format, depends on the protocol is used.

This method gets:
	Intrfc is the Firewall Interface
*/
func (c PClient) ShowInterface(Intrfc string) ([]byte, error) {

	switch c.Settings.Api {
	// To do: testRouteFibLookupRST
	/*
		case 0: // REST API
			{
				return ......
			}
	*/
	case 1: // XML API
		{
			url, err := c.showInterfaceXML(Intrfc)
			if err != nil {
				return nil, err
			}

			b, err := c.Dial(url, "GET")
			if err != nil {
				return nil, err
			}

			return b, nil
		}
	default:
		{
			return nil, errors.New("Wrong type of API is used.")
		}
	}
}

/*
GetZoneFromInt uses ShowInterface to get interface info, then parses the XML or Jason (depends on what API is used) response to get only Zone Name field of that.

This method gets:
	Intrfc is the Firewall Interface
*/
func (c PClient) GetZoneFromInt(Intrfc string) (string, error) {

	// Get Source Zone Info info
	result, err := c.ShowInterface(Intrfc)
	if err != nil {
		return "", nil
	}

	// Parse the output
	switch c.Settings.Api {
	// To do:
	/*
		case 0: // REST API
			{
				return .....
			}
	*/
	case 1: // XML API
		{
			ifnet, err := paloalto.ParseXMLIfNet(string(result))
			if err != nil {
				return "", nil
			}
			return ifnet.Result.Ifnet.Zone, nil
		}
	default:
		{
			return "", errors.New("Wrong type of API is used.")
		}
	}

}

/*
showInterfaceXML generates an URL to get firewall interface information using Palo Alto XML API. This corresponds the command 'show interface <interface>' in CLI.
Output will be in XML format.

This method gets:
	fip is Firewall IP Address
	Intrfc is the Firewall Interface
*/
func (c PClient) showInterfaceXML(Intrfc string) (url string, err error) {

	url = "https://" + c.Fip + "/api/?type=op&cmd=<show><interface>" + Intrfc
	url = url + "</interface></show>"

	switch c.Settings.Auth {

	case 0: // Using Key/Token
		{
			url = url + "&key=" + c.Settings.Key
			return url, nil
		}
	case 1: // Using Basic User/Pass
		{
			return url, nil
		}
	default:
		{
			return "", errors.New("Wrong type of athentication method is used.")
		}
	}
}

/*
showInterfaceRST generates an URL to get firewall interface information using Palo Alto REST API. This corresponds the command 'show interface <interface>' in CLI.
Output will be in JSON format.

This method gets:
	fip is Firewall IP Address
	Intrfc is the Firewall Interface
*/
func (c PClient) showInterfaceRST(Intrfc string) (url string, err error) {
	// To Do
	//
	return "", nil
}

/*
TestSecurityPolicyMatch gets firewall policy match for a given config (source, destination, Zones, ports, application).
It uses different protocols (REST/XML API) and authentication methods (Key/Token or Basic User/Pass) based on what is set for PClient settings.
Output will be in XML/Jason format, depends on the protocol is used.

This method gets cfg that is an 7-cell array in which:

	cfg[0] is Protocol Number (e.g. 6 means TCP)
	cfg[1] is Source Zone
	cfg[2] is Destination Zone
	cfg[3] is Source IP
	cfg[4] is Destination IP
	cfg[5] is Destination Port
	cfg[6] is Application*/
func (c PClient) TestSecurityPolicyMatch(cfg [7]string) ([]byte, error) {

	switch c.Settings.Api {
	// To do: testRouteFibLookupRST
	/*
		case 0: // REST API
			{
				return ....
			}
	*/
	case 1: // XML API
		{
			url, err := c.testSecurityPolicyMatchXML(cfg)
			if err != nil {
				return nil, err
			}

			b, err := c.Dial(url, "GET")
			if err != nil {
				return nil, err
			}

			return b, nil
		}
	default:
		{
			return nil, errors.New("Wrong type of API is used.")
		}
	}
}

/*
GetZoneFromInt uses TestSecurityPolicyMatch to get Test Security Policy Match result, then parses the XML or Jason (depends on what API is used) response to get only Action field of that.

This method gets cfg that is an 7-cell array in which:
	cfg[0] is Protocol Number (e.g. 6 means TCP)
	cfg[1] is Source Zone
	cfg[2] is Destination Zone
	cfg[3] is Source IP
	cfg[4] is Destination IP
	cfg[5] is Destination Port
	cfg[6] is Application
*/
func (c PClient) GetPolicyMatch(cfg [7]string) (string, error) {

	// Get Test Security Policy Match result
	result, err := c.TestSecurityPolicyMatch(cfg)
	if err != nil {
		return "", err
	}

	// Parse the output
	switch c.Settings.Api {
	// To do:
	/*
		case 0: // REST API
			{
				return .....
			}
	*/
	case 1: // XML API
		{
			plcm, err := paloalto.ParseXMLPolicyMatch(string(result))
			if err != nil {
				return "", err
			}

			return plcm.Result.Rules.Entry.Action, nil
		}
	default:
		{
			return "", errors.New("Wrong type of API is used.")
		}
	}
}

/*
testSecurityPolicyMatchXML generates an URL to be used to get firewall interface information. This coresonds corresponds
the command 'test security-policy-match protocol <protocol> from <source-zone> to <destination-zone> source <source-ip-address>
destination <destination-ip-address> destination-port <destination-port> application <application-name>' in CLI but here is used on firewall XML API.
Output will be in XML format.

This method gets cfg that is an 7-cell array in which:
	cfg[0] is Protocol Number (e.g. 6 means TCP)
	cfg[1] is Source Zone
	cfg[2] is Destination Zone
	cfg[3] is Source IP
	cfg[4] is Destination IP
	cfg[5] is Destination Port
	cfg[6] is Application
*/
func (c PClient) testSecurityPolicyMatchXML(cfg [7]string) (url string, err error) {

	if cfg[0] == "" {
		return "", errors.New("Fist parameter should be protocol number!\n")
	}
	if cfg[1] == "" {
		return "", errors.New("Second parameter should be Source Zone!\n")
	}
	if cfg[2] == "" {
		return "", errors.New("Third parameter should be Destination Zone!\n")
	}
	if cfg[3] == "" {
		return "", errors.New("Fourth parameter should be Source IP!\n")
	}
	if cfg[4] == "" {
		return "", errors.New("Fifth parameter should be Destination IP!\n")
	}
	if cfg[5] == "" {
		return "", errors.New("Sixth parameter should be Destination Port!\n")
	}

	url = "https://" + c.Fip + "/api/?type=op&cmd="
	url = url + "<test><security-policy-match>"
	url = url + "<protocol>" + cfg[0] + "</protocol>"
	url = url + "<from>" + cfg[1] + "</from><to>" + cfg[2] + "</to>"
	url = url + "<source>" + cfg[3] + "</source><destination>" + cfg[4] + "</destination>"
	url = url + "<destination-port>" + cfg[5] + "</destination-port>"

	if cfg[6] != "nil" {
		url = url + "<application>" + cfg[6] + "</application>"
	}

	url = url + "</security-policy-match></test>"

	switch c.Settings.Auth {
	case 0: // Using Key/Token
		{
			url = url + "&key=" + c.Settings.Key
			return url, nil
		}
	case 1: // Using Basic User/Pass
		{
			return url, nil
		}
	default:
		{
			return "", errors.New("Wrong type of athentication method is used.")
		}
	}
}

/*
testSecurityPolicyMatchXML generates an URL to be used to get firewall interface information. This coresonds corresponds
the command 'test security-policy-match protocol <protocol> from <source-zone> to <destination-zone> source <source-ip-address>
destination <destination-ip-address> destination-port <destination-port> application <application-name>' in CLI but here is used on firewall REST API.
Output will be in JSON format.

This method gets cfg that is an 7-cell array in which:
	cfg[0] is Protocol Number (e.g. 6 means TCP)
	cfg[1] is Source Zone
	cfg[2] is Destination Zone
	cfg[3] is Source IP
	cfg[4] is Destination IP
	cfg[5] is Destination Port
	cfg[6] is Application
*/
func (c PClient) testSecurityPolicyMatchRST(fip string, cfg [7]string, key string) ([]byte, error) {
	// To Do
	//
	return nil, nil
}

func (c PClient) FindObjectAddress() ([]byte, error) {
	// To Do
	//
	return nil, nil
}

// REST Network
// https://192.168.1.249/restapi/v9.1/Network/SDWANInterfaceProfiles
// https://192.168.1.249/restapi/v9.1/Network/EthernetInterfaces?name=ethernet1/1
// https://192.168.1.249/restapi/v9.1/Network/VirtualRouters?name=default

// REST Get Object names
// https://192.168.1.249/restapi/v9.1/Objects/Addresses?location=vsys&vsys=vsys1
// https://192.168.1.249/restapi/v9.1/Objects/Addresses?location=vsys&vsys=vsys1&name=Eth1_1.1.1.254_24
// https://192.168.1.249/restapi/v9.1/Objects/AddressGroups?location=vsys&vsys=vsys1&name=TestObject

// REST Get Firewall Policy
// https://192.168.1.249/restapi/v9.1/Policies/SecurityRules?location=vsys&vsys=vsys1&name=Z1-Z2
// https://192.168.1.249/restapi/v9.1/Policies/SecurityRules?location=vsys&vsys=vsys1&source=HOST_10.1.0.1

// Push Frewall Policy
