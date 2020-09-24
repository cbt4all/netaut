package palapi

import (
	"crypto/tls"
	"errors"
	"io/ioutil"
	"net"
	"net/http"
)

const (
	httpsPort = "443"
)

// ClientSettings helps us to add settings on some function we are using. For example, if we want to use username and password to login to the firewalls or are we
// using token/Keys and based on this settings different authentication methods are use while logininig to firewall. Other things can be set here is to choose which
// type of APIs we want to use (REST API or XML API)
type ClientSettings struct {
	Auth     int    // Authentication method (0 means Key/Token and 1 = User/Pass)
	Api      int    // The API should be used (0 means REST API and 1 means XML API)
	Key      string // key is Token/Key should be takan manually from firewall
	Username string // If not using Token/Key to login to firewall need to use username and password
	Password string // If not using Token/Key to login to firewall need to use username and password
}

// NewClientSettings takes all parameters needed and returns a new ClientSettings
func NewClientSettings(api, auth int, key, user, pass string) (*ClientSettings, error) {

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

type PClient struct {
	// ClientSettings helps us to add settings on some function we are using.
	Settings *ClientSettings

	// Fip is Firewall IP that the PClient should connect to
	Fip string

	// If custome port should be used while connecting to firewall
	Port string

	// Since HTTPS is used, sometimes the certificate is not intalled on the computer the program is run on. So if SkipCertVerify is 'true', it means
	// TLSClientConfig in http.Transport will use &tls.Config{InsecureSkipVerify: true}
	SkipCertVerify bool
}

// NewPClient takes all parameters needed and returns a new PClient
func NewPClient(cs *ClientSettings, fip, p string, certSkip bool) (*PClient, error) {

	c := new(PClient)

	c.Settings = cs

	// Fip is Firewall IP that the PClient should connect to
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

// Dial ... --------------------------
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

// TestRouteFibLookupApi generates REST/XML URL to be used to get firewall FIB information. This coresonds corresponds
// the command 'test routing fib-lookup virtual-router <virtual-router> ip <ip-address>' in CLI but here is used on firewall REST/XML API.
// Output will be in XML/Jason format, depends on how the parameter 'api' is used.
//
// What this function dose is to call either testRouteFibLookupRST or testRouteFibLookupXML to generate REST/XML URL respectively. So if TestRouteFibLookupApi
// is called by 'api=rest', testRouteFibLookupRST is used and if is called bu 'api=xml' testRouteFibLookupXML is called. The parameters are:
// fip is Firewall IP
// vr is Virtual-Router
// dip is Destination IP
// key is Token/Key should be takan manually from firewall
// api is the API type you want to use. For now it can be either 'rest' or 'xml'
func (c PClient) TestRouteFibLookup(vr, dip string) ([]byte, error) {

	switch c.Settings.Api {
	// To do: testRouteFibLookupRST
	/*
		case 0: // REST API
			{
				return testRouteFibLookupRST(vr, dip)
			}
	*/
	case 1: // XML API
		{
			url, err := c.testRouteFibLookupXML(vr, dip)
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

// testRouteFibLookupXML generates an URL to be used to get firewall FIB information. This coresonds corresponds
// the command 'test routing fib-lookup virtual-router <virtual-router> ip <ip-address>' in CLI but here is used on firewall XML API.
// Output will be in XML format. In the command we have:
// fip is Firewall IP
// vr is Virtual-Router
// dip is Destination IP
// key is Token/Key should be takan manually from firewall
func (c PClient) testRouteFibLookupXML(vr, dip string) (url string, err error) {

	url = "https://" + c.Fip + "/api/?type=op&cmd=<test><routing><fib-lookup><virtual-router>" + vr + "</virtual-router>"
	url = url + "<ip>" + dip + "</ip></fib-lookup></routing></test>"

	switch c.Settings.Auth {
	case 0: // Using Key/Token
		{
			url = "&key=" + c.Settings.Key
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

// testRouteFibLookupRST generates REST URL to be used to get firewall FIB information. This coresonds corresponds
// the command 'test routing fib-lookup virtual-router <virtual-router> ip <ip-address>' in CLI but here is used on firewall REST API.
// Output will be in XML format. In the command we have:
// fip is Firewall IP
// vr is Virtual-Router
// dip is Destination IP
// key is Token/Key should be takan manually from firewall
func (c PClient) testRouteFibLookupRST(fip, vr, dip, key string) ([]byte, error) {
	// To Do
	// https://192.168.1.249/restapi/v9.1/Network/VirtualRouters
	return nil, nil
}

// ShowInterface generates REST/XML URL to be used to get firewall interface information. This coresonds corresponds
// the command 'show interface <interface>' in CLI but here is used on firewall REST/XML API.
// Output will be in XML/Jason format, depends on how the parameter 'api' is used.
// fip is Firewall IP
// Intrfc is the interface we want
// key is Token/Key should be takan manually from firewall
// api is the API type you want to use. For now it can be either 'rest' or 'xml'
func (c PClient) ShowInterface(Intrfc string) ([]byte, error) {

	switch c.Settings.Api {
	// To do: testRouteFibLookupRST
	/*
		case 0: // REST API
			{
				return showInterfaceXML(vr, dip)
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

// showInterfaceXML generates XML URL to be used to get firewall interface information. This coresonds corresponds
// the command 'show interface <interface>' in CLI but here is used on firewall XML API.
// Output will be in XML format. In the command we have:
// fip is Firewall IP
// Intrfc is the interface we want
// key is Token/Key should be takan manually from firewall
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

// showInterfaceRST generates REST URL to be used to get firewall interface information. This coresonds corresponds
// the command 'show interface <interface>' in CLI but here is used on firewall REST API.
// Output will be in XML format. In the command we have:
// fip is Firewall IP
// Intrfc is the interface we want
// key is Token/Key should be takan manually from firewall
func (c PClient) showInterfaceRST(fip, vr, dip, key string) ([]byte, error) {
	// To Do
	//
	return nil, nil
}

// TestSecurityPolicyMatch generates REST/XML URL to be used to get firewall policy match. This coresonds corresponds
// the command 'test security-policy-match protocol 6 from <source-zone> to <destination-zone> source <source-ip-address>
// destination <destination-ip-address> destination-port <destination-port> application <application-name>
// Output will be in XML/Jason format, depends on how the parameter 'api' is used.
// fip is Firewall IP
// cfg is an 7-cell array in which we put these:
// cfg[0] is Protocol Number (e.g. 6)
// cfg[1] is Source Zone
// cfg[2] is Destination Zone
// cfg[3] is Source IP
// cfg[4] is Destination IP
// cfg[5] is Destination Port
// cfg[6] is Application
// key is Token/Key should be takan manually from firewall
// api is the API type you want to use. For now it can be either 'rest' or 'xml'
func (c PClient) TestSecurityPolicyMatch(cfg [7]string) ([]byte, error) {

	switch c.Settings.Api {
	// To do: testRouteFibLookupRST
	/*
		case 0: // REST API
			{
				return showInterfaceXML(vr, dip)
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

// testSecurityPolicyMatchXML generates an URL to be used to get firewall interface information. This coresonds corresponds
// the command 'test security-policy-match protocol 6 from <source-zone> to <destination-zone> source <source-ip-address>
// destination <destination-ip-address> destination-port <destination-port> application <application-name>' in CLI but here is used on firewall XML API.
// Output will be in XML format
// fip is Firewall IP
// cfg is an 7-cell array in which we put these:
// cfg[0] is Protocol Number (e.g. 6)
// cfg[1] is Source Zone
// cfg[2] is Destination Zone
// cfg[3] is Source IP
// cfg[4] is Destination IP
// cfg[5] is Destination Port
// cfg[6] is Application
// key is Token/Key should be takan manually from firewall
func (c PClient) testSecurityPolicyMatchXML(cfg [7]string) (url string, err error) {

	if cfg[0] == "" {
		return "", errors.New("Fist parameter should be protocol number!\n")
	}
	if cfg[1] == "" {
		return "", errors.New("Second parameter should be Source Zone!\n")
	}
	if cfg[2] == "" {
		return "", errors.New("Fist parameter should be Destination Zone!\n")
	}
	if cfg[3] == "" {
		return "", errors.New("Fist parameter should be Source IP!\n")
	}
	if cfg[4] == "" {
		return "", errors.New("Fist parameter should be Destination IP!\n")
	}
	if cfg[5] == "" {
		return "", errors.New("Fist parameter should be Destination Port!\n")
	}

	url = "https://" + c.Fip + "/api/?type=op&cmd="
	url = url + "<test><security-policy-match>"
	url = url + "<protocol>" + cfg[0] + "</protocol>"
	url = url + "<from>" + cfg[1] + "</from><to>" + cfg[2] + "</to>"
	url = url + "<source>" + cfg[3] + "</source><destination>" + cfg[4] + "</destination>"
	url = url + "<destination-port>" + cfg[5] + "</destination-port>"

	if cfg[6] != "nil" {
		url = url + " application "
		url = url + "<application>" + cfg[6] + "</application>"
	}

	url = url + "</security-policy-match></test>"

	switch c.Settings.Auth {
	case 0: // Using Key/Token
		{
			url = url + "key=" + c.Settings.Key
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

// testSecurityPolicyMatchRST generates REST URL to be used to get firewall interface information. This coresonds corresponds
// the command 'test security-policy-match protocol 6 from <source-zone> to <destination-zone> source <source-ip-address>
// destination <destination-ip-address> destination-port <destination-port> application <application-name>' in CLI but here is used on firewall REST API.
// Output will be in JSON format
// fip is Firewall IP
// cfg is an 7-cell array in which we put these:
// cfg[0] is Protocol Number (e.g. 6)
// cfg[1] is Source Zone
// cfg[2] is Destination Zone
// cfg[3] is Source IP
// cfg[4] is Destination IP
// cfg[5] is Destination Port
// cfg[6] is Application
// key is Token/Key should be takan manually from firewall
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
