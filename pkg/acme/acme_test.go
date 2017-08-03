package acme

import (
	"reflect"
	"testing"

	"github.com/StackExchange/dnscontrol/models"
)

func TestGetCerts(t *testing.T) {
	var d1, d2 *models.DomainConfig

	tst := func(desc string, f func(), expect map[string][]string) {
		t.Run(desc, func(t *testing.T) {

			d1 = &models.DomainConfig{
				Name: "a.com",
				Records: []*models.RecordConfig{
					{Name: "@", NameFQDN: "a.com", Type: "A", Metadata: map[string]string{}},
					{Name: "foo", NameFQDN: "foo.a.com", Type: "A", Metadata: map[string]string{}},
				},
				Metadata: map[string]string{},
			}
			d2 = &models.DomainConfig{
				Name: "b.com",
				Records: []*models.RecordConfig{
					{Name: "@", NameFQDN: "b.com", Type: "A", Metadata: map[string]string{}},
					{Name: "foo", NameFQDN: "foo.b.com", Type: "A", Metadata: map[string]string{}},
				},
				Metadata: map[string]string{},
			}
			if f != nil {
				f()
			}
			cfg := &models.DNSConfig{Domains: []*models.DomainConfig{d1, d2}}
			cp := &challengeProvider{cfg: cfg}
			certs := cp.GetCertificates()
			if !reflect.DeepEqual(certs, expect) {
				t.Fatalf("%s is not %s", certs, expect)
			}
		})
	}

	tst("simple", nil, map[string][]string{
		"a.com": []string{"a.com", "foo.a.com"},
		"b.com": []string{"b.com", "foo.b.com"},
	})

	tst("domain cert names", func() {
		d1.Metadata[metaSanName] = "acom"
		d2.Metadata[metaSanName] = "bcom"
	}, map[string][]string{
		"acom": []string{"a.com", "foo.a.com"},
		"bcom": []string{"b.com", "foo.b.com"},
	})

	tst("everything one cert", func() {
		d1.Metadata[metaSanName] = "all"
		d2.Metadata[metaSanName] = "all"
	}, map[string][]string{
		"all": []string{"a.com", "b.com", "foo.a.com", "foo.b.com"},
	})

	tst("single record override", func() {
		d1.Metadata[metaSanName] = "all"
		d2.Records[1].Metadata[metaSanName] = "all"
	}, map[string][]string{
		"all":   []string{"a.com", "foo.a.com", "foo.b.com"},
		"b.com": []string{"b.com"},
	})

	tst("ignore domain", func() {
		d1.Metadata[metaSanName] = "-"
	}, map[string][]string{
		"b.com": []string{"b.com", "foo.b.com"},
	})

	tst("ignore record", func() {
		d1.Records[1].Metadata[metaSanName] = "-"
	}, map[string][]string{
		"a.com": []string{"foo.a.com"},
		"b.com": []string{"b.com", "foo.b.com"},
	})

	tst("ignore domain", func() {
		d1.Metadata[metaSanName] = "-"
		d1.Records[0].Metadata[metaSanName] = "a"
	}, map[string][]string{
		"a":     []string{"foo.a.com"},
		"b.com": []string{"b.com", "foo.b.com"},
	})

}

//Possible metadata
// domain metadata:
// cert:explicit (default: false)  // require records to ask to be generated with san_name / include
// cert:nosan                      // generate a cert per name
// cert:subjects                   // manually specify names to include (comma seperated). This will matter more as wildcards are supported. (do we require names to all be in the zone?)
// cert:wildcards (default: false) // not supported yet, but should plan for it. Can switch default later.

// record metadata:
// cert:include // override explicit_only, using domain's san
// cert:single  // don't include in domain, make specific cert for this record. Sugar for {"cert:name":"$fqdn"}
// cert:subject // subject to use

// global flags (cli likely)
// implicit (default: false) // generate certs for domains without cert:* metadata
// explicit                  // add cert:explicit:true to all domains
// wildcards                 // add cert:wildcards:true to all domains
