//Package namedotcom implements a registrar that uses the name.com api to set name servers. It will self register it's providers when imported.
package namedotcom

import (
	"encoding/json"
	"fmt"

	"github.com/StackExchange/dnscontrol/providers"
)

var docNotes = providers.DocumentationNotes{
	providers.DocDualHost:            providers.Cannot("Apex NS records not editable"),
	providers.DocCreateDomains:       providers.Cannot("New domains require registration"),
	providers.DocOfficiallySupported: providers.Can(),
	providers.CanUsePTR:              providers.Cannot("PTR records are not supported (See Link)", "https://www.name.com/support/articles/205188508-Reverse-DNS-records"),
}

type nameDotCom struct {
	APIUrl  string `json:"apiurl"`
	APIUser string `json:"apiuser"`
	APIKey  string `json:"apikey"`
}

func init() {
	providers.RegisterRegistrarType("NAMEDOTCOM", newReg)
	providers.RegisterDomainServiceProviderType("NAMEDOTCOM", newDsp, providers.CanUseAlias, providers.CanUseSRV, docNotes)
}

func newReg(conf map[string]string) (providers.Registrar, error) {
	return newProvider(conf)
}

func newDsp(conf map[string]string, meta json.RawMessage) (providers.DNSServiceProvider, error) {
	return newProvider(conf)
}

func newProvider(conf map[string]string) (*nameDotCom, error) {
	api := &nameDotCom{}
	api.APIUser, api.APIKey, api.APIUrl = conf["apiuser"], conf["apikey"], conf["apiurl"]
	if api.APIKey == "" || api.APIUser == "" {
		return nil, fmt.Errorf("name.com apikey and apiuser must be provided in creds.json")
	}
	if api.APIUrl == "" {
		api.APIUrl = defaultAPIBase
	}
	return api, nil
}
