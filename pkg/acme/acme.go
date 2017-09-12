package acme

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"log"
	"sort"

	"github.com/StackExchange/dnscontrol/models"
	"github.com/StackExchange/dnscontrol/providers"
	"github.com/xenolf/lego/acme"
)

type challengeProvider struct {
	cfg       *models.DNSConfig
	providers map[string]providers.DNSServiceProvider
}

type CertValidator interface {
	CreateACMETXTRecord(name, content string) error
	RemoveACMETXTRecords() error
}

func (c *challengeProvider) Present(domain, token, keyAuth string) error {
	fmt.Println("PRESENT!!!!", domain, token, keyAuth)
	fqdn, value, _ := acme.DNS01Record(domain, keyAuth)
	fmt.Println(fqdn, value)
	return nil
}
func (c *challengeProvider) CleanUp(domain, token, keyAuth string) error {
	fmt.Println("CLEAN!!!!", domain, token, keyAuth)
	// for all appropriate providers on domain, remove all LE TXT records.
	return nil
}

const (
	// san certificate name to use for domain or record certificate. "cert:certName":"-" will not generate cert for name.
	metaSanName = "cert:certName"
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
	// TODO: validate provider compatibility

	//TODO: load from disk
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
			key:   privateKey,
		}
	}

	client, err := acme.NewClient("https://acme-v01.api.letsencrypt.org/directory", u, acme.RSA2048)
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
		log.Println("REG", u.Registration)
		//TODO: save to disk
		j, _ := json.Marshal(u)
		fmt.Println(string(j))
	}

	err = client.AgreeToTOS()
	if err != nil {
		log.Fatal(err)
	}

	for name, names := range challenge.GetCertificates() {
		// Find existing and renew if needed. Otherwise re-issue
		log.Println(name, names)
		cert, errs := client.ObtainCertificate(names, true, nil, false)
		log.Println(cert, errs)
	}
	return nil
}

func loadUser() (*user, error) {
	return nil, nil
}

type user struct {
	Email        string
	Registration *acme.RegistrationResource
	key          crypto.PrivateKey
}

func (u *user) GetEmail() string {
	return u.Email
}
func (u *user) GetRegistration() *acme.RegistrationResource {
	return u.Registration
}
func (u *user) GetPrivateKey() crypto.PrivateKey {
	return u.key
}
