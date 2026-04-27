package cmd

import (
	"context"
	"fmt"
	"github.com/DNS-MSMT-INET/yodns/resolver"
	"github.com/DNS-MSMT-INET/yodns/resolver/model"
	"github.com/DNS-MSMT-INET/yodns/resolver/serialization"
	"github.com/miekg/dns"
	"github.com/spf13/cobra"
	"golang.org/x/exp/slices"
	"os"
	"path"
	"strings"
	"time"
)

// Auth NS server not responding => A/AAAA has err
// Record/Name does not exist => "IPs" is empty
type validationResult struct {
	Domains []resolver.TaggedDomainName `json:"domains"`
	Errors  []string                    `json:"errors"`
}

var Validate = &cobra.Command{
	Use:   "validate",
	Short: "Validates yodns output",
	Long:  "Validates yodns output. This command performs basic sanity checks, to ensure that the scanner behaves as intended.",
	Run: func(cmd *cobra.Command, args []string) {
		in := Must(cmd.Flags().GetString("in"))
		out := Must(cmd.Flags().GetString("out"))
		zip := Must(cmd.Flags().GetString("zip"))
		printnoerr := Must(cmd.Flags().GetBool("printnoerr"))
		domains := Must(cmd.Flags().GetStringSlice("domain"))

		zipAlgo, compression, err := serialization.ParseZip(zip)
		if err != nil {
			panic(err)
		}

		// Unless format is explicitly set, try to infer it from the in-path
		format := Must(cmd.Flags().GetString("format"))
		if !cmd.Flag("format").Changed {
			format = Must(inferFormat(in))
		}

		trustedTLDsStr := Must(cmd.Flags().GetStringSlice("trustedTLDs"))
		trustedTLDs := make([]model.DomainName, 0, len(trustedTLDsStr))
		for _, tld := range trustedTLDsStr {
			trustedTLDs = append(trustedTLDs, model.DomainName(tld))
		}

		c := make(chan resolver.Result, 200)
		reader := getFilteredReaderZip(in, format, false, nil, 5*time.Minute)
		go func() {
			if err := reader.ReadTo(c); err != nil {
				panic(fmt.Sprintf("%v: %v", in, err))
			}
		}()

		if err := os.MkdirAll(path.Dir(out), 0700); err != nil {
			panic(err)
		}

		w, closeFunc, err := getZipFileWriter(out, zipAlgo, compression)
		if err != nil {
			panic(err)
		}
		defer closeFunc()

		domainFilter := DomainFilter(domains)
		for p := range c {
			if len(domains) > 0 && !domainFilter(p) {
				continue
			}

			workDone := make(chan bool)
			doTheWork := func() {
				defer func() {
					workDone <- true
				}()

				r := validationResult{
					Domains: p.Domains,
				}

				r.Errors = validateNoZoneExistsTwice(p)

				for _, domain := range p.Domains {
					r.Errors = append(r.Errors, validateQueryChain(domain.Name, []uint16{dns.TypeAAAA, dns.TypeA, dns.TypeTXT}, p, trustedTLDs)...)
				}

				r.Errors = append(r.Errors, validateCNAMES(p, trustedTLDs)...)

				zoneNames, _ := getZoneNamesAndServers(p)
				for _, zoneName := range zoneNames {
					r.Errors = append(r.Errors, validateZone(zoneName, p, trustedTLDs)...)
				}

				r.Errors = append(r.Errors, validateNS(p)...)

				// More assertions
				// Every found A record is entered as a name server IP
				// Something with CNAMEs?

				if len(r.Errors) == 0 && !printnoerr {
					return
				}

				writeResult(w, r)
			}

			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			go doTheWork()
			select {
			case <-ctx.Done():
				fmt.Println(fmt.Sprintf("Timed out for: %v", p.Domains))
				cancel()
			case <-workDone:
				cancel()
			}
		}
	},
}

func getZoneNamesAndServers(p resolver.Result) ([]model.DomainName, []*model.NameServer) {
	zones := p.Zone.Flatten()
	zoneNames := make([]model.DomainName, 0, len(zones))
	nses := make([]*model.NameServer, 0)

	for _, z := range zones {
		zoneNames = append(zoneNames, z.Name)

		for _, ns := range z.NameServers {
			nses = append(nses, ns)
		}
	}

	return zoneNames, nses
}

func validateCNAMES(p resolver.Result, trustedTLDs []model.DomainName) []string {
	cnames := make(map[model.DomainName]any)
	for iter := p.Msgs.Iterate(); iter.HasNext(); {
		msg := iter.Next()
		if msg.Message == nil || !msg.Metadata.IsFinal {
			continue
		}

		// We don't follow up on _dmarc and MX
		if strings.HasPrefix(string(msg.OriginalQuestion.Name), "_dmarc") {
			continue
		}
		if msg.OriginalQuestion.Type == dns.TypeMX {
			continue
		}

		for _, rec := range msg.Message.Answer {
			if cnameRec, isCname := rec.(*dns.CNAME); isCname {
				cnames[model.MustNewDomainName(cnameRec.Target)] = nil
			}
		}
	}

	var result []string
	for cname := range cnames {
		result = append(result, validateQueryChain(cname, []uint16{dns.TypeA, dns.TypeAAAA, dns.TypeTXT}, p, trustedTLDs)...)
	}
	return result
}

func validateZone(name model.DomainName, p resolver.Result, trustedTLDs []model.DomainName) []string {
	if name.EqualString(".") {
		return nil
	}

	var result []string
	result = append(result, validateQueryChain(name, []uint16{dns.TypeSOA, dns.TypeMX, dns.TypeTXT}, p, trustedTLDs)...)
	zone := p.Zone.GetClosestEnclosingZone(name)

	result = append(result, assertQueryPerZone("version.bind.", dns.TypeTXT, zone, p, trustedTLDs)...)

	if dmarc, dmarcErr := name.PrependLabel("_dmarc"); dmarcErr == nil {
		if !zone.Name.IsTopLevelDomain() { // We don't ask TLDs for _dmarc
			result = append(result, assertQueryPerZone(dmarc, dns.TypeTXT, zone, p, trustedTLDs)...)
		}
	}

	result = append(result, assertQueryPerZone(name, dns.TypeDS, zone, p, trustedTLDs)...)
	result = append(result, assertQueryPerZone(name, dns.TypeDNSKEY, zone, p, trustedTLDs)...)
	result = append(result, assertQueryPerZone(name, dns.TypeCDS, zone, p, trustedTLDs)...)
	result = append(result, assertQueryPerZone(name, dns.TypeCDNSKEY, zone, p, trustedTLDs)...)
	result = append(result, assertQueryPerZone(name, dns.TypeCSYNC, zone, p, trustedTLDs)...)

	if !zone.Name.IsTopLevelDomain() {
		result = append(result, assertQueryPerZone(name, dns.TypeCAA, zone, p, trustedTLDs)...)
	}

	if zone.Parent == nil {
		return result
	}

	result = append(result, assertQueryPerZone(name, dns.TypeDS, zone.Parent, p, trustedTLDs)...)
	result = append(result, assertQueryPerZone(name, dns.TypeDNSKEY, zone.Parent, p, trustedTLDs)...)

	return result
}

func validateNS(p resolver.Result) []string {
	type nsToZone struct {
		nsName   model.DomainName
		zoneName model.DomainName
	}

	var nstozones []nsToZone
	isFromCname := make(map[model.DomainName]*model.Zone)
	zoneMap := make(map[model.DomainName]*model.Zone)
	for _, zone := range p.Zone.Flatten() {
		zoneMap[zone.Name] = zone
	}

	for iter := p.Msgs.Iterate(); iter.HasNext(); {
		msg := iter.Next()
		if msg.Message == nil || !msg.Metadata.IsFinal {
			continue
		}

		// We don't follow these
		if msg.OriginalQuestion.Type == dns.TypeMX {
			continue
		}
		if msg.OriginalQuestion.Name.EqualString("version.bind.") {
			continue
		}
		if strings.HasPrefix(string(msg.OriginalQuestion.Name), "_dmarc.") {
			continue
		}

		isCnameResponse := false
		for _, rec := range msg.Message.Answer {
			if _, isCname := rec.(*dns.CNAME); isCname {
				isCnameResponse = true
				break
			}
		}

		for _, rec := range msg.Message.Ns {
			if nsRec, isNs := rec.(*dns.NS); isNs {
				nsname := model.MustNewDomainName(nsRec.Ns)
				zonename := model.MustNewDomainName(nsRec.Hdr.Name)

				// Sometimes we get entries like '. NS ns1.pendingrenewaldeletion.com.'
				// or bogus referrals
				z := p.Zone.GetClosestEnclosingZone(msg.OriginalQuestion.Name)
				if !zonename.IsSubDomainOf(z.Name) {
					continue
				}

				if zonename.EqualString(".") {
					continue
				}

				if strings.Contains(string(zonename), "localhost") {
					continue
				}

				nstozones = append(nstozones, nsToZone{nsName: nsname, zoneName: zonename})
				if isCnameResponse {
					isFromCname[zonename] = nil
				}
			}
		}

		for _, rec := range msg.Message.Answer {
			if nsRec, isNs := rec.(*dns.NS); isNs {
				nsname := model.MustNewDomainName(nsRec.Ns)
				zonename := model.MustNewDomainName(nsRec.Hdr.Name)

				// Sometimes we get entries like '. NS ns1.pendingrenewaldeletion.com.'
				if !msg.OriginalQuestion.Name.IsSubDomainOf(zonename) {
					continue
				}
				if strings.Contains(string(zonename), "localhost") {
					continue
				}

				nstozones = append(nstozones, nsToZone{nsName: nsname, zoneName: zonename})
				if isCnameResponse {
					isFromCname[zonename] = nil
				}
			}
		}
	}

	var validationErrs []string
	for _, nstozone := range nstozones {
		foundNs := false
		_, fromCname := isFromCname[nstozone.zoneName]
		if _, ok := zoneMap[nstozone.zoneName]; !ok && !fromCname {
			validationErrs = append(validationErrs, fmt.Sprintf("Zone %v was not found in result but in a record in a message to %v", nstozone.zoneName, nstozone.nsName))
			continue
		}

		if fromCname {
			continue
		}

		for _, ns := range zoneMap[nstozone.zoneName].NameServers {
			if ns.Name.Equal(nstozone.nsName) {
				foundNs = true
				break
			}
		}

		if !foundNs {
			validationErrs = append(validationErrs, fmt.Sprintf("NS %v was found in message, but not in zone %v", nstozone.nsName, nstozone.zoneName))
		}
	}

	return validationErrs
}

func validateNoZoneExistsTwice(p resolver.Result) []string {
	names := make(map[model.DomainName]int)
	var errs []string
	for _, zone := range p.Zone.Flatten() {
		i, _ := names[zone.Name]
		names[zone.Name] = i + 1
	}

	for name, count := range names {
		if count > 1 {
			errs = append(errs, fmt.Sprintf("Zone %v exists %v times", name, count))
		}
	}
	return errs
}

// validateQueryChain validates the query chain up to a certain name.
// It is used to check the output of the resolver for completeness.
// A valid query chain must not necessarily ask for the name itself in the end.
// It can be interrupted if a server in the chain convinces us that it is not authoritative or that the name does not exist.
func validateQueryChain(qName model.DomainName,
	qTypes []uint16,
	p resolver.Result,
	trustedTLD []model.DomainName) []string {
	labels := qName.GetLabels()

	var validationErrs []string
	for i := 2; i <= len(labels); i++ {
		partName := qName.GetAncestor(i)
		validationErrs = append(validationErrs, assertQueryPerZone(partName, dns.TypeNS, p.Zone.GetClosestEnclosingZone(partName), p, trustedTLD)...)
	}

	for _, qtype := range qTypes {
		validationErrs = append(validationErrs, assertQueryPerZone(qName, qtype, p.Zone.GetClosestEnclosingZone(qName), p, trustedTLD)...)
	}

	return validationErrs
}

func assertQueryPerZone(qName model.DomainName, qType uint16, authZone *model.Zone, p resolver.Result, trustedTLD []model.DomainName) []string {
	var validationErrs []string
	queriesAsked := 0
	for _, ns := range authZone.NameServers {
		for _, ip := range ns.IPAddresses.Items() {
			queryAsked := false
			for iter := p.Msgs.GetMessagesByName(ip, qName); iter.HasNext(); {
				msg := iter.Next()
				if msg.OriginalQuestion.Type == qType {
					queryAsked = true
					queriesAsked++
					break
				}
			}
			if !queryAsked && !slices.Contains(trustedTLD, authZone.Name) {
				validationErrs = append(validationErrs, fmt.Sprintf("missing %v query for name %v to %v (%v)", qType, qName, ip, ns.Name))
			}
		}
	}

	if queriesAsked == 0 && slices.Contains(trustedTLD, qName) {
		validationErrs = append(validationErrs, fmt.Sprintf("missing %v query for name %v", qType, qName))
	}

	// For NS queries, ensure that they have been asked to the parent, too (if the qname is the zone apex)
	if authZone.Parent != nil &&
		qName.Equal(authZone.Name) &&
		qType == dns.TypeNS {
		queriesAsked = 0
		for _, ns := range authZone.Parent.NameServers {
			for _, ip := range ns.IPAddresses.Items() {
				nsQueryAsked := false
				for iter := p.Msgs.GetMessagesByName(ip, qName); iter.HasNext(); {
					msg := iter.Next()
					if msg.OriginalQuestion.Type == dns.TypeNS {
						nsQueryAsked = true
						queriesAsked++
						break
					}
				}
				if !nsQueryAsked && !slices.Contains(trustedTLD, authZone.Parent.Name) {
					validationErrs = append(validationErrs, fmt.Sprintf("missing %v query for name %v to parent ns %v (%v)", qType, qName, ip, ns.Name))
				}
			}
		}
		if queriesAsked == 0 && slices.Contains(trustedTLD, qName) {
			validationErrs = append(validationErrs, fmt.Sprintf("missing %v query for name %v in parent zone", qType, qName))
		}
	}

	return validationErrs
}

func init() {
	rootCmd.AddCommand(Validate)

	Validate.Flags().String("in", "", "")
	Validate.Flags().String("out", "", "")
	Validate.Flags().String("format", "protobuf", "")
	Validate.Flags().String("zip", "", "Zips the output")
	Validate.Flags().Bool("printnoerr", false, "Also prints the entries that have no errors")
	Validate.Flags().StringSlice("domain", []string{}, "Filters the output by target domain name")
	Validate.Flags().StringSlice("trustedTLDs", []string{}, "Top Level domains which are trusted")
}
