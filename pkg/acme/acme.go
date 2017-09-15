package acme

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/miekg/dns/dnsutil"

	"github.com/StackExchange/dnscontrol/models"
	"github.com/StackExchange/dnscontrol/providers"
	"github.com/xenolf/lego/acme"
)

type challengeProvider struct {
	cfg       *models.DNSConfig
	providers map[string]providers.DNSServiceProvider
}

type CertValidator interface {
	CreateACMETXTRecord(domain, name, content string) error
	RemoveACMETXTRecords(domain string) error
}

func (c *challengeProvider) getValidators(domain string) (name string, validators []CertValidator, err error) {
	// we have a domain name. It may or may not have extra subdomains.
	// find longest domain which is our suffix
	var dom *models.DomainConfig
	for _, d := range c.cfg.Domains {
		if strings.HasSuffix(domain, d.Name) {
			if dom == nil || len(dom.Name) < len(d.Name) {
				dom = d
			}
		}
	}
	if dom == nil {
		return "", nil, fmt.Errorf("Domain %s not found", domain)
	}
	for pName := range dom.DNSProviders {
		var p providers.DNSServiceProvider
		var ok bool
		var validator CertValidator
		if p, ok = c.providers[pName]; !ok {
			return "", nil, fmt.Errorf("Provider %s not found", pName)
		}
		if validator, ok = p.(CertValidator); !ok {
			return "", nil, fmt.Errorf("Provider %s does not implement ACME provider", pName)
		}
		validators = append(validators, validator)
	}
	return dom.Name, validators, nil
}

func (c *challengeProvider) Present(domain, token, keyAuth string) error {
	// find the domain
	name, validators, err := c.getValidators(domain)
	if err != nil {
		return err
	}
	fqdn, value, _ := acme.DNS01Record(domain, keyAuth)
	for _, v := range validators {
		if err := v.CreateACMETXTRecord(name, dnsutil.TrimDomainName(fqdn, name), value); err != nil {
			return err
		}
	}
	return nil
}

func (c *challengeProvider) CleanUp(domain, token, keyAuth string) error {
	name, validators, err := c.getValidators(domain)
	if err != nil {
		return err
	}
	for _, v := range validators {
		if err := v.RemoveACMETXTRecords(name); err != nil {
			return err
		}
	}
	return nil
}

const (
	// san certificate name to use for domain or record certificate. "certName":"-" will not generate cert for name.
	metaSanName = "certName"
)

// r types we infer we want certs from by default
var autoRecordTypes = map[string]bool{
	"A":     true,
	"AAAA":  true,
	"CNAME": true,
	"MX":    true,
	"ALIAS": true,
}

// map of certname -> list of names to include
func (c *challengeProvider) GetCertificates() map[string][]string {
	// certname to lookup of included sans
	certs := map[string]map[string]bool{}
	add := func(cert, name string) {
		if certs[cert] == nil {
			certs[cert] = map[string]bool{}
		}
		certs[cert][name] = true
	}
	for _, d := range c.cfg.Domains {
		dName := d.Name
		if sName := d.Metadata[metaSanName]; sName != "" {
			dName = sName
		}
		for _, r := range d.Records {
			certName := dName
			if rName := r.Metadata[metaSanName]; rName != "" {
				certName = rName
			} else if !autoRecordTypes[r.Type] {
				// not explicitly stated, not an automatic record type
				continue
			}
			if certName == "-" {
				continue
			}
			add(certName, r.NameFQDN)
		}
	}
	// now convert to proper map for return
	out := map[string][]string{}
	for name, m := range certs {
		for k := range m {
			out[name] = append(out[name], k)
		}
		sort.Strings(out[name])
	}
	return out
}

func IssueCerts(cfg *models.DNSConfig, providers map[string]providers.DNSServiceProvider) error {
	challenge := &challengeProvider{cfg: cfg, providers: providers}
	// TODO: validate provider compatibility up front

	os.MkdirAll("certs", 0600)

	u, err := loadUser()
	if err != nil {
		return err
	}
	if u == nil {
		privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			log.Fatal(err)
		}
		u = &user{
			Email: "you@yours.com",
			Key:   privateKey,
		}
	}

	client, err := acme.NewClient("https://acme-staging.api.letsencrypt.org/directory", u, acme.RSA2048)
	if err != nil {
		return err
	}
	client.SetChallengeProvider(acme.DNS01, challenge)
	client.ExcludeChallenges([]acme.Challenge{acme.HTTP01, acme.TLSSNI01})

	if u.Registration == nil {
		reg, err := client.Register()
		if err != nil {
			return err
		}
		u.Registration = reg
		j, _ := json.Marshal(u)
		ioutil.WriteFile(filepath.Join("certs", "user.json"), j, 0600)
	}

	err = client.AgreeToTOS()
	if err != nil {
		log.Fatal(err)
	}

	for name, names := range challenge.GetCertificates() {
		// Find existing and renew if needed. Otherwise re-issue
		log.Println(name, names)
		cert, errs := client.ObtainCertificate(names, true, nil, false)
		if len(errs) > 0 {
			for _, err := range errs {
				log.Println(err)
			}
		}
		ioutil.WriteFile(filepath.Join("certs", fmt.Sprintf("%s.cert", name)), cert.Certificate, 0600)
		ioutil.WriteFile(filepath.Join("certs", fmt.Sprintf("%s.key", name)), cert.PrivateKey, 0600)
		ioutil.WriteFile(filepath.Join("certs", fmt.Sprintf("%s.issuer.cert", name)), cert.IssuerCertificate, 0600)
	}
	return nil
}

func loadUser() (*user, error) {
	dat, err := ioutil.ReadFile(filepath.Join("certs", "user.json"))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	u := &user{}
	err = json.Unmarshal(dat, u)
	if err != nil {
		return nil, err
	}
	return u, nil
}

type user struct {
	Email        string
	Registration *acme.RegistrationResource
	Key          *rsa.PrivateKey
}

func (u *user) GetEmail() string {
	return u.Email
}
func (u *user) GetRegistration() *acme.RegistrationResource {
	return u.Registration
}
func (u *user) GetPrivateKey() crypto.PrivateKey {
	return u.Key
}
