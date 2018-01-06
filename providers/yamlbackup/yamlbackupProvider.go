package yamlbackup

/*

yamlbackup -
  Generate human-readable YAML files of the zones.  The format is
	intended to be compatible with OctoDNS but this has not been tested.
	This does not support OctoDNS's GeoDNS syntax; OctoDNS does not support
	our pseudo record types.

	Since this is intended only for creating backup files, we do
	not do the pretty diff'ing that providers like BIND does.
*/

import (
	"bytes"
	"encoding/json"
	"fmt"

	"github.com/StackExchange/dnscontrol/models"
	"github.com/StackExchange/dnscontrol/providers"
)

var features = providers.DocumentationNotes{
	providers.CanUseCAA:              providers.Can(),
	providers.CanUsePTR:              providers.Can(),
	providers.CanUseSRV:              providers.Can(),
	providers.CanUseTLSA:             providers.Can(),
	providers.CanUseTXTMulti:         providers.Can(),
	providers.CantUseNOPURGE:         providers.Cannot(),
	providers.DocCreateDomains:       providers.Can("Driver just maintains list of zone files. It should automatically add missing ones."),
	providers.DocDualHost:            providers.Can(),
	providers.DocOfficiallySupported: providers.Can(),
}

func initYamlbackup(config map[string]string, providermeta json.RawMessage) (providers.DNSServiceProvider, error) {
	// config -- the key/values from creds.json
	// meta -- the json blob from NewReq('name', 'TYPE', meta)
	api := &ProviderHandle{
		directory: config["directory"],
	}
	if api.directory == "" {
		api.directory = "zones"
	}
	if len(providermeta) != 0 {
		err := json.Unmarshal(providermeta, api)
		if err != nil {
			return nil, err
		}
	}
	//	api.nameservers = models.StringsToNameservers(api.DefaultNS)
	return api, nil
}

func init() {
	providers.RegisterDomainServiceProviderType("YAMLBACKUP", initYamlbackup, features)
}

type ProviderHandle struct {
	//nameservers []*models.Nameserver
	directory string
}

func (c *ProviderHandle) GetNameservers(string) ([]*models.Nameserver, error) {
	return nil, nil
}

func (c *ProviderHandle) GetDomainCorrections(dc *models.DomainConfig) ([]*models.Correction, error) {
	dc.Punycode()
	// Phase 1: Copy everything to []*models.RecordConfig:
	//    expectedRecords < dc.Records[i]
	//    foundRecords < zonefile
	//
	// Phase 2: Do any manipulations:
	// add NS
	// manipulate SOA
	//
	// Phase 3: Convert to []diff.Records and compare:
	// expectedDiffRecords < expectedRecords
	// foundDiffRecords < foundRecords
	// diff.Inc...(foundDiffRecords, expectedDiffRecords )

	// Default SOA record.  If we see one in the zone, this will be replaced.
	//soaRec := makeDefaultSOA(c.DefaultSoa, dc.Name)

	// Read foundRecords:
	//	foundRecords := make([]*models.RecordConfig, 0)
	//	var oldSerial, newSerial uint32
	//zonefile := filepath.Join(c.directory, strings.Replace(strings.ToLower(dc.Name), "/", "_", -1)+".zone")
	//foundFH, err := os.Open(zonefile)
	//zoneFileFound := err == nil
	//	if err != nil && !os.IsNotExist(os.ErrNotExist) {
	//		// Don't whine if the file doesn't exist. However all other
	//		// errors will be reported.
	//		fmt.Printf("Could not read zonefile: %v\n", err)
	//	} else {
	//		for x := range dns.ParseZone(foundFH, dc.Name, zonefile) {
	//			if x.Error != nil {
	//				log.Println("Error in zonefile:", x.Error)
	//			} else {
	//				rec, serial := rrToRecord(x.RR, dc.Name, oldSerial)
	//				if serial != 0 && oldSerial != 0 {
	//					log.Fatalf("Multiple SOA records in zonefile: %v\n", zonefile)
	//				}
	//				if serial != 0 {
	//					// This was an SOA record. Update the serial.
	//					oldSerial = serial
	//					newSerial = generate_serial(oldSerial)
	//					// Regenerate with new serial:
	//					*soaRec, _ = rrToRecord(x.RR, dc.Name, newSerial)
	//					rec = *soaRec
	//				}
	//				foundRecords = append(foundRecords, &rec)
	//			}
	//		}
	//	}

	// Add SOA record to expected set:
	//	if !dc.HasRecordTypeName("SOA", "@") {
	//		dc.Records = append(dc.Records, soaRec)
	//	}

	// Normalize
	//models.PostProcessRecords(foundRecords)

	//differ := diff.New(dc)
	//_, create, del, mod := differ.IncrementalDiff(foundRecords)

	buf := &bytes.Buffer{}
	//	// Print a list of changes. Generate an actual change that is the zone
	//	changes := false
	//	for _, i := range create {
	//		changes = true
	//		if zoneFileFound {
	//			fmt.Fprintln(buf, i)
	//		}
	//	}
	//	for _, i := range del {
	//		changes = true
	//		if zoneFileFound {
	//			fmt.Fprintln(buf, i)
	//		}
	//	}
	//	for _, i := range mod {
	//		changes = true
	//		if zoneFileFound {
	//			fmt.Fprintln(buf, i)
	//		}
	//	}
	msg := fmt.Sprintf("GENERATE_ZONEFILE: %s\n", dc.Name)
	//	if !zoneFileFound {
	//msg = msg + fmt.Sprintf(" (%d records)\n", len(create))
	//	}
	msg += buf.String()
	corrections := []*models.Correction{}
	//	if changes {
	//		corrections = append(corrections,
	//			&models.Correction{
	//				Msg: msg,
	//				F: func() error {
	//					fmt.Printf("CREATING ZONEFILE: %v\n", zonefile)
	//					zf, err := os.Create(zonefile)
	//					if err != nil {
	//						log.Fatalf("Could not create zonefile: %v", err)
	//					}
	//					zonefilerecords := make([]dns.RR, 0, len(dc.Records))
	//					for _, r := range dc.Records {
	//						zonefilerecords = append(zonefilerecords, r.ToRR())
	//					}
	//					err = WriteZoneFile(zf, zonefilerecords, dc.Name)
	//
	//					if err != nil {
	//						log.Fatalf("WriteZoneFile error: %v\n", err)
	//					}
	//					err = zf.Close()
	//					if err != nil {
	//						log.Fatalf("Closing: %v", err)
	//					}
	//					return nil
	//				},
	//			})
	//	}

	return corrections, nil
}
