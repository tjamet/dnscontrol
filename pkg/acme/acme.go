package acme

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
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
}

func (c *challengeProvider) Present(domain, token, keyAuth string) error {
	fmt.Println("PRESENT!!!!", domain, token, keyAuth)
	// for all appropriate providers on domain, add TXT record.
	return nil
}
func (c *challengeProvider) CleanUp(domain, token, keyAuth string) error {
	fmt.Println("CLEAN!!!!", domain, token, keyAuth)
	// for all appropriate providers on domain, remove all LE TXT records.
	return nil
}

const (
	// san certificate name to use for
	metaSanName = "cert:certName"
)

// map of certname -> list of names to include
func (c *challengeProvider) GetCertificates() map[string][]string {
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
	log.Println(challenge)

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatal(err)
	}
	//LOAD
	myUser := &MyUser{
		Email: "you@yours.com",
		key:   privateKey,
	}

	client, err := acme.NewClient("https://acme-v01.api.letsencrypt.org/directory", myUser, acme.RSA2048)
	log.Println(client)
	if err != nil {
		log.Fatal(err)
	}
	client.SetChallengeProvider(acme.DNS01, challenge)
	client.ExcludeChallenges([]acme.Challenge{acme.HTTP01, acme.TLSSNI01})

	if myUser.Registration == nil {
		reg, err := client.Register()
		if err != nil {
			log.Fatal(err)
		}
		myUser.Registration = reg
		log.Println("REG", myUser.Registration)
		// SAVE
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

type MyUser struct {
	Email        string
	Registration *acme.RegistrationResource
	key          crypto.PrivateKey
}

func (u *MyUser) GetEmail() string {
	return u.Email
}
func (u *MyUser) GetRegistration() *acme.RegistrationResource {
	return u.Registration
}
func (u *MyUser) GetPrivateKey() crypto.PrivateKey {
	return u.key
}
