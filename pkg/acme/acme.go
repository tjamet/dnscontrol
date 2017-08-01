package acme

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"log"

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

// map of certname -> list of names to include
func (c *challengeProvider) GetCertificates() map[string][]string {
	// domain metadata:
	// cert:name (default: $domain)   // san cert group
	// cert:explicit (default: false) // require records to ask to be generated with san_name / include
	// cert:nosan                     // generate a cert per name

	// record metadata:
	// cert:name (default: domain's san)
	// cert:include // override explicit_only, using domain's san
	// cert:single  // don't include in domain, make specific cert for this record. Sugar for {"cert:name":"$fqdn"}

	// global flags (cli likely)
	// implicit (default: false) // generate certs for domains without cert: metadata
	// explicit_default          // add cert:explicit to all domains
	return map[string][]string{
		"stackoverflow.com": []string{"captncraig.io", "foo.captncraig.io"},
	}
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
