package namedotcom

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/miekg/dns/dnsutil"

	"github.com/StackExchange/dnscontrol/models"
	"github.com/StackExchange/dnscontrol/providers/diff"
)

var defaultNameservers = []*models.Nameserver{
	{Name: "ns1.name.com"},
	{Name: "ns2.name.com"},
	{Name: "ns3.name.com"},
	{Name: "ns4.name.com"},
}

func (n *nameDotCom) GetDomainCorrections(dc *models.DomainConfig) ([]*models.Correction, error) {

	// Process the desired records:

	dc.Punycode()

	// Get and process the existing records:

	rawRecords, err := n.getRecords(dc.Name)
	if err != nil {
		return nil, err
	}
	existingRecords := make([]*models.RecordConfig, len(rawRecords))
	for i, r := range rawRecords {
		existingRecords[i] = r.toRecord()
	}
	checkNSModifications(dc)
	models.Downcase(existingRecords)

	// Diff desired vs. existing:

	differ := diff.New(dc)
	_, create, del, mod := differ.IncrementalDiff(existingRecords)

	// Process corrections:

	corrections := []*models.Correction{}

	for _, d := range del {
		rec := d.Existing.Original.(*protocolRawRecord)
		c := &models.Correction{Msg: d.String(), F: func() error { return n.deleteRecord(rec.RecordID, dc.Name) }}
		corrections = append(corrections, c)
	}
	for _, cre := range create {
		rec := cre.Desired
		c := &models.Correction{Msg: cre.String(), F: func() error { return n.createRecord(rec, dc.Name) }}
		corrections = append(corrections, c)
	}
	for _, chng := range mod {
		old := chng.Existing.Original.(*protocolRawRecord)
		new := chng.Desired
		c := &models.Correction{Msg: chng.String(), F: func() error {
			err := n.deleteRecord(old.RecordID, dc.Name)
			if err != nil {
				return err
			}
			return n.createRecord(new, dc.Name)
		}}
		corrections = append(corrections, c)
	}

	return corrections, nil
}

func checkNSModifications(dc *models.DomainConfig) {
	newList := make([]*models.RecordConfig, 0, len(dc.Records))
	for _, rec := range dc.Records {
		if rec.Type == "NS" && rec.NameFQDN == dc.Name {
			continue // Apex NS rawRecords are automatically created for the domain's nameservers and cannot be managed otherwise via the name.com API.
		}
		newList = append(newList, rec)
	}
	dc.Records = newList
}

// toRecord converts r to a RecordConfig
func (r *protocolRawRecord) toRecord() *models.RecordConfig {
	ttl, _ := strconv.ParseUint(r.TTL, 10, 32)
	prio, _ := strconv.ParseUint(r.Priority, 10, 16)
	rc := &models.RecordConfig{
		NameFQDN: r.Name,
		Type:     r.Type,
		Target:   r.Content,
		TTL:      uint32(ttl),
		Original: r,
	}

	// Mark FQDNs as such:
	if rc.Type == "CNAME" || rc.Type == "ANAME" || rc.Type == "MX" || rc.Type == "NS" {
		rc.Target = r.Content + "."
	}

	// NDC's "ALIAS" is the same as the new DNS rtype "ANAME".
	if rc.Type == "ALIAS" {
		r.Type = "ANAME"
	}

	switch r.Type { // #rtype_variations
	case "A", "AAAA", "CNAME", "NS", "TXT":
		// nothing additional.
	case "MX":
		rc.MxPreference = uint16(prio)
	case "SRV":
		parts := strings.Split(r.Content, " ")
		weight, _ := strconv.ParseInt(parts[0], 10, 32)
		port, _ := strconv.ParseInt(parts[1], 10, 32)
		rc.SrvWeight = uint16(weight)
		rc.SrvPort = uint16(port)
		rc.SrvPriority = uint16(prio)
		rc.MxPreference = 0
		rc.Target = parts[2] + "."
	default:
		panic(fmt.Sprintf("toRecord unimplemented rtype %v", r.Type))
		// We panic so that we quickly find any switch statements
		// that have not been updated for a new RR type.
	}
	return rc
}

func (n *nameDotCom) createRecord(rc *models.RecordConfig, domain string) error {
	target := rc.Target
	if rc.Type == "CNAME" || rc.Type == "ANAME" || rc.Type == "MX" || rc.Type == "NS" {
		if target[len(target)-1] == '.' {
			target = target[:len(target)-1]
		} else {
			return fmt.Errorf("unexpected. CNAME/MX/NS target did not end with dot")
		}
	}
	dat := struct {
		Hostname string `json:"hostname"`
		Type     string `json:"type"`
		Content  string `json:"content"`
		TTL      uint32 `json:"ttl,omitempty"`
		Priority uint16 `json:"priority,omitempty"`
	}{
		Hostname: dnsutil.TrimDomainName(rc.NameFQDN, domain),
		Type:     rc.Type,
		Content:  target,
		TTL:      rc.TTL,
		Priority: rc.MxPreference,
	}
	if dat.Hostname == "@" {
		dat.Hostname = ""
	}
	switch rc.Type { // #rtype_variations
	case "A", "AAAA", "ANAME", "CNAME", "MX", "NS", "TXT":
		// nothing
	case "SRV":
		dat.Content = fmt.Sprintf("%d %d %v", rc.SrvWeight, rc.SrvPort, rc.Target)
		dat.Priority = rc.SrvPriority
	default:
		panic(fmt.Sprintf("createRecord rtype %v unimplemented", rc.Type))
		// We panic so that we quickly find any switch statements
		// that have not been updated for a new RR type.
	}
	resp, err := n.post(n.apiCreateRecord(domain), dat)
	if err != nil {
		return err
	}
	return resp.getErr()
}

func (n *nameDotCom) deleteRecord(id, domain string) error {
	dat := struct {
		ID string `json:"record_id"`
	}{id}
	resp, err := n.post(n.apiDeleteRecord(domain), dat)
	if err != nil {
		return err
	}
	return resp.getErr()
}
