package cmd

import (
	"fmt"
	"github.com/rs/zerolog"
	"github.com/spf13/cobra"
	"github.com/DNS-MSMT-INET/yodns/resolver"
	"github.com/DNS-MSMT-INET/yodns/resolver/common"
	"github.com/DNS-MSMT-INET/yodns/resolver/serialization"
	"math"
	"os"
	"strings"
	"time"
)

var ExtractActiveDomains = &cobra.Command{
	Use:   "extractActiveDomains",
	Short: "Extracts the domains that were being scanned during the specified time interval",
	Run: func(cmd *cobra.Command, args []string) {
		in := Must(cmd.Flags().GetString("in"))
		out := Must(cmd.Flags().GetString("out"))
		from := Must(cmd.Flags().GetInt64("from"))
		to := Must(cmd.Flags().GetInt64("to"))
		requireTags := Must(cmd.Flags().GetBool("require-tags"))
		zip := Must(cmd.Flags().GetString("zip"))
		resultFilters := []FilterPredicate[resolver.Result]{
			ResultFromFilter(time.Unix(from, 0)),
			ResultToFilter(time.Unix(to, 0))}

		logger := zerolog.New(os.Stderr).Level(zerolog.InfoLevel).With().Timestamp().Logger()

		zipAlgo, compression, err := serialization.ParseZip(zip)
		if err != nil {
			panic(err)
		}

		c := make(chan resolver.Result, 200)
		reader := getFilteredReaderZip(in, "protobuf", false, nil, 5*time.Minute, resultFilters...)
		go func() {
			if err := reader.ReadTo(c); err != nil {
				panic(err)
			}
		}()

		outFile, closeFunc, err := getZipFileWriter(out, zipAlgo, compression)
		if err != nil {
			panic(err)
		}
		defer closeFunc()

		if _, err := outFile.Write([]byte("Domain,Idx,Tags,Start,Duration,File\n")); err != nil {
			panic(err)
		}

		i := 0
		for p := range c {
			if i += 1; i%1000 == 0 {
				logger.Info().Msgf("Processing domain %v", i)
			}

			var sb strings.Builder
			for _, dn := range p.Domains {
				tags := common.ToMap(strings.Split(dn.Tags, ";")...)
				tags = keepSourceTags(tags)
				if requireTags && len(tags) == 0 {
					continue
				}

				sb.Write([]byte(fmt.Sprintf("%v,%v,%v,%v,%v,%v\n", dn.Name, dn.Idx, dn.Tags, p.StartTime.Unix(), p.Duration.Milliseconds(), in)))
			}

			if _, err := outFile.Write([]byte(sb.String())); err != nil {
				panic(err)
			}
		}
	},
}

func init() {
	rootCmd.AddCommand(ExtractActiveDomains)

	ExtractActiveDomains.Flags().String("in", "", "")
	ExtractActiveDomains.Flags().Bool("require-tags", true, "")
	ExtractActiveDomains.Flags().String("zip", "zstd:fast", "")
	ExtractActiveDomains.Flags().String("out", "active_domains.csv", "")
	ExtractActiveDomains.Flags().Int64("from", 0, "")
	ExtractActiveDomains.Flags().Int64("to", math.MaxInt64/2, "")

}
