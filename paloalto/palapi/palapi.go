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
	Auth     int    // Authentication method (0=REST API and 1 = XML API)
	Api      string // xml or rest
	Key      string // key is Token/Key should be takan manually from firewall
	Username string // If not using Token/Key to login to firewall need to use username and password
	Password string // If not using Token/Key to login to firewall need to use username and password
}

// NewClientSettings takes all parameters needed and returns a new ClientSettings
func NewClientSettings(api, auth int, key, user, pass string) (cs *ClientSettings, err error) {

	// Choose which API should be used
	switch api {
	case 0: // REST API is used
		{
			cs.Api = "rest"
		}

	case 1: // XML API is used
		{
			cs.Api = "xml"
		}
	}

	// Choose which authentication method should be used
	cs.Auth = auth
	switch auth {
	case 0: // Key is used
		{
			if key == "" {
				return nil, errors.New("Key is selected to ues but not entered.")
			}
			cs.Key = key
		}

	case 1: // Basic Username/Password is used
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
func NewPClient(cs *ClientSettings, fip, p string, certSkip bool) (c *PClient, err error) {

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

func TestSecurityPolicyMatch(fip string, cfg [7]string, key, api string) ([]byte, error) {

	switch api {
	// To do: testSecurityPolicyMatchRST
	/*
		case "rest":
			{
				return testSecurityPolicyMatchRST(fip, Intrfc, key)
			}
	*/
	case "xml":
		{
			return testSecurityPolicyMatchXML(fip, cfg, key)
		}
	default:
		{
			return nil, errors.New("wrong type of API is used.")
		}
	}

	return nil, errors.New("wrong type of API is used.")
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
func testSecurityPolicyMatchXML(fip string, cfg [7]string, key string) ([]byte, error) {

	if cfg[0] == "" {
		return nil, errors.New("Fist parameter should be protocol number!\n")
	}
	if cfg[1] == "" {
		return nil, errors.New("Second parameter should be Source Zone!\n")
	}
	if cfg[2] == "" {
		return nil, errors.New("Fist parameter should be Destination Zone!\n")
	}
	if cfg[3] == "" {
		return nil, errors.New("Fist parameter should be Source IP!\n")
	}
	if cfg[4] == "" {
		return nil, errors.New("Fist parameter should be Destination IP!\n")
	}
	if cfg[5] == "" {
		return nil, errors.New("Fist parameter should be Destination Port!\n")
	}

	url := "https://" + fip + "/api/?type=op&cmd="
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
	url = url + "&key=" + key

	method := "GET"

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	client := &http.Client{Transport: tr}

	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		return nil, err
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
func testSecurityPolicyMatchRST(fip string, cfg [7]string, key string) ([]byte, error) {
	// To Do
	//
	return nil, nil
}

func FindObjectAddress() ([]byte, error) {
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
