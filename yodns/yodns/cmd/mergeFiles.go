package cmd

import (
	"cmp"
	"fmt"
	"github.com/rs/zerolog"
	"github.com/spf13/cobra"
	"github.com/DNS-MSMT-INET/yodns/resolver"
	"github.com/DNS-MSMT-INET/yodns/resolver/serialization"
	"os"
	"slices"
	"strings"
	"sync"
	"time"
)

var MergeFiles = &cobra.Command{
	Use:   "mergeFiles",
	Short: "Processes input files of various length to create output files of fixed size.",
	Long: "This command reprocesses the input files of various length to create output files of fixed size. " +
		"Every file (except for the last) is expected to be 'full', i.e. has the maximum number " +
		"of items. Additionally, this command can perform deduplication.",
	Run: func(cmd *cobra.Command, args []string) {
		in := Must(cmd.Flags().GetString("in"))
		zip := Must(cmd.Flags().GetString("zip"))
		outDir := Must(cmd.Flags().GetString("out-dir"))
		format := Must(cmd.Flags().GetString("format"))
		dedup := Must(cmd.Flags().GetBool("dedup"))
		logLevel := Must(cmd.Flags().GetString("loglevel"))
		size := Must(cmd.Flags().GetUint("size"))

		l, err := zerolog.ParseLevel(logLevel)
		if err != nil {
			panic(err)
		}
		if err := os.MkdirAll(outDir, os.ModePerm); err != nil {
			panic(err)
		}

		logger := zerolog.New(os.Stderr).Level(l).With().Timestamp().Logger()

		zipAlgo, zipCompression, err := serialization.ParseZip(zip)
		if err != nil {
			panic(err)
		}

		var dedupMap *sync.Map
		if dedup {
			dedupMap = new(sync.Map)
		}

		c := make(chan resolver.Result, 200)
		reader := getFilteredReaderZip(in, format, false, nil, 5*time.Minute)
		go func() {
			defer func() {
				if r := recover(); r != nil {
					panic(fmt.Errorf("%v %v", outDir, r))
				}
			}()

			if err := reader.ReadTo(c); err != nil {
				panic(fmt.Errorf("%v %w", outDir, err))
			}
		}()

		writer := getParallelWriter(outDir, size, format, zipAlgo, zipCompression, 1)

		i := 0
		for p := range c {
			if i++; i%10_000 == 0 {
				logger.Info().Msgf("Processing domains %v", i)
			}

			// Get all domains that have a non-empty tag (the others are computed, we don't care here)
			domainsWithTags := make([]resolver.TaggedDomainName, 0, len(p.Domains)/2)
			for _, dn := range p.Domains {
				if dn.Tags != "" {
					domainsWithTags = append(domainsWithTags, dn)
				}
			}

			if dedupMap != nil {
				// Sort and create a unique key for the resolution
				slices.SortFunc(domainsWithTags, func(a, b resolver.TaggedDomainName) int {
					return cmp.Compare(a.Name, b.Name)
				})
				var key strings.Builder
				for _, dn := range domainsWithTags {
					if _, err := key.WriteString(string(dn.Name)); err != nil {
						panic(err)
					}
				}

				// Already seen this...
				if _, loaded := dedupMap.LoadOrStore(key.String(), nil); loaded {
					continue
				}
			}

			for _, dn := range domainsWithTags {
				logger.Debug().Msgf("%v,%v", dn.Name, dn.Tags)
			}

			if err := writer.WriteAsync(p); err != nil {
				panic(err)
			}
		}

		if err := writer.Wait(); err != nil {
			panic(err)
		}
	},
}

func init() {
	rootCmd.AddCommand(MergeFiles)

	MergeFiles.Flags().String("in", "", "Input file")
	MergeFiles.Flags().String("out-dir", "", "Output directory of the filtered data")
	MergeFiles.Flags().String("format", "protobuf", "File format. Protobuf or json.")
	MergeFiles.Flags().String("zip", "zstd:best", "Whether and how to zip the output.")
	MergeFiles.Flags().Bool("dedup", false, "Whether to search and discard duplicate entries.")
	MergeFiles.Flags().String("loglevel", "info", "Log level to use")
	MergeFiles.Flags().Uint("size", 500, "Number of items to use in each file")
}
