package cmd

import (
	"fmt"
	"github.com/spf13/cobra"
	"github.com/DNS-MSMT-INET/yodns/resolver"
	"github.com/DNS-MSMT-INET/yodns/resolver/common"
	"github.com/DNS-MSMT-INET/yodns/resolver/serialization"
	"github.com/DNS-MSMT-INET/yodns/resolver/serialization/protobuf"
	"io"
	"os"
	"path"
	"strings"
	"time"
)

var FilterCZDS = &cobra.Command{
	Use:   "filterCZDS",
	Short: "Removes the domain resolutions associated with ICANNs CZDS from the data.",
	Long: "Removes the domain resolutions associated with ICANNs CZDS from the data. " +
		"This is necessary, as CZDS data must not be shared in a way that allows reconstruction of the data set. " +
		"Since CZDS domains are all second level domains, filtering works as follows: " +
		"Each file contains multiple resolutions. Each resolution contains a batch of domains that share a SLD (or more). " +
		"First, remove all CZDS tags. CZDS tags are necessarily at the second level. " +
		"If there are no other tags in the target domain, remove the entire resolution from the file. " +
		"However, if there is any other tag (at the second level or below), " +
		"we can keep the entire resolution, as we have learned about the existence of the SLD from another source.",
	Run: func(cmd *cobra.Command, args []string) {
		in := Must(cmd.Flags().GetString("in"))
		out := Must(cmd.Flags().GetString("out"))
		czdsOut := Must(cmd.Flags().GetString("czds-out"))
		format := Must(cmd.Flags().GetString("format"))

		if err := os.MkdirAll(path.Dir(out), os.ModePerm); err != nil {
			panic(err)
		}
		if err := os.MkdirAll(path.Dir(czdsOut), os.ModePerm); err != nil {
			panic(err)
		}

		var outWriter io.Writer
		var czdsOutWriter io.Writer

		c := make(chan resolver.Result, 200)
		reader := getFilteredReaderZip(in, format, false, nil, 5*time.Minute)
		go func() {
			defer func() {
				if r := recover(); r != nil {
					panic(fmt.Errorf("%v %v", out, r))
				}
			}()

			if err := reader.ReadTo(c); err != nil {
				panic(fmt.Errorf("%v %w", out, err))
			}
		}()

		for p := range c {

			if shouldRemove(p.Domains) {
				if czdsOutWriter == nil {
					w, closeFunc, err := getZipFileWriter(czdsOut, serialization.ZipZSTD, serialization.CompressionBest)
					if err != nil {
						panic(err)
					}
					czdsOutWriter = w
					defer closeFunc()
				}

				if err := protobuf.SerializeResult(p, czdsOutWriter, protobuf.ToMessage); err != nil {
					panic(err)
				}

				continue
			}

			f := filterCZDSFromResult(p)
			if outWriter == nil {
				w, closeFunc, err := getZipFileWriter(out, serialization.ZipZSTD, serialization.CompressionBest)
				if err != nil {
					panic(err)
				}
				outWriter = w
				defer closeFunc()
			}

			if err := protobuf.SerializeResult(*f, outWriter, protobuf.ToMessage); err != nil {
				panic(err)
			}
		}
	},
}

func filterCZDSFromResult(p resolver.Result) *resolver.Result {
	// CZDS domains: tag "zf", possibly also "rescan"
	// Not se, ch, nu, li, ee,
	domainsFiltered := make([]resolver.TaggedDomainName, 0, len(p.Domains))
	for _, z := range p.Domains {
		// Remove the ZF tag for all domains except the publicly available zone transfers
		if !isFromZoneTransfer(z) {
			tags := common.ToMap(strings.Split(z.Tags, ";")...)
			delete(tags, TagZF)
			z.Tags = strings.Join(common.Keys(tags), ";")
		}

		domainsFiltered = append(domainsFiltered, z)
	}
	p.Domains = domainsFiltered

	return &p
}

// If we find any name, that is not from CZDS, we can keep the entire resolution.
// Because CZDS names are always SLDs, non-czds names are at the same level or deeper,
// so they include the name we learned from CZDS.
func shouldRemove(dn []resolver.TaggedDomainName) bool {
	for _, dn := range dn {
		// Remove all but the tags that indicate where a domain comes from
		tags := common.ToMap(strings.Split(dn.Tags, ";")...)
		tags = keepSourceTags(tags)

		// No tags => Computed name like www.{name}
		if len(tags) == 0 {
			continue
		}

		// Domains under these TLDs have the "zf" tag but are not from CZDS - we can keep them.
		if isFromZoneTransfer(dn) {
			return false
		}

		// At least on other tag
		if len(tags) > 1 {
			return false
		}

		// Only one tag, and it is not "zf" - allowed to keep.
		if _, ok := tags[TagZF]; !ok && len(tags) == 1 {
			return false
		}
	}

	// Did not find any other tags than "zf" - we have to remove.
	return true
}

func isFromZoneTransfer(dn resolver.TaggedDomainName) bool {
	return dn.Name.IsSubDomainOf(".se") ||
		dn.Name.IsSubDomainOf(".ch") ||
		dn.Name.IsSubDomainOf(".nu") ||
		dn.Name.IsSubDomainOf(".li") ||
		dn.Name.IsSubDomainOf(".ee")
}

// Removes all tags that are not used to identify a domain source.
// Will keep tags like 'ct', 'rad' or 'zf', will discard tags like 'rescan', 'tra100k', 'cert'
func keepSourceTags(tags map[string]any) map[string]any {
	filtered := make(map[string]any)
	for t := range tags {
		if _, ok := SourceTags[t]; ok {
			filtered[t] = nil
		}
	}
	return filtered
}

func init() {
	rootCmd.AddCommand(FilterCZDS)

	FilterCZDS.Flags().String("in", "", "Input file")
	FilterCZDS.Flags().String("log", "", "Log file")
	FilterCZDS.Flags().String("out", "", "Output file")
	FilterCZDS.Flags().String("czds-out", "", "Output file for CZDS domains")
	FilterCZDS.Flags().String("format", "protobuf", "File format. Protobuf or json.")
	FilterCZDS.Flags().Bool("zip", true, "Whether to zip the output.")
}
