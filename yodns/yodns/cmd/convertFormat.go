package cmd

import (
	"bufio"
	"fmt"
	"github.com/DNS-MSMT-INET/yodns/resolver"
	"github.com/DNS-MSMT-INET/yodns/resolver/serialization"
	"github.com/DNS-MSMT-INET/yodns/resolver/serialization/json"
	"github.com/DNS-MSMT-INET/yodns/resolver/serialization/protobuf"
	"github.com/spf13/cobra"
	"io"
	"os"
	"time"
)

type reader interface {
	ReadTo(outChan chan<- resolver.Result) error
}

type writer interface {
	Wait() error
	WriteAsync(result resolver.Result) error
}

var ConvertFormat = &cobra.Command{
	Use:     "convertFormat",
	Short:   "Converts yodns output from protobuf to json and vice versa.",
	Long:    "Converts yodns output from protobuf to json and vice versa.",
	Example: "convertFormat --in 'data/scan/*.pb.zst' --out 'data/json' --size 10",
	Run: func(cmd *cobra.Command, args []string) {
		in := Must(cmd.Flags().GetString("in"))
		from := Must(cmd.Flags().GetString("from"))
		out := Must(cmd.Flags().GetString("out"))
		to := Must(cmd.Flags().GetString("to"))
		zip := Must(cmd.Flags().GetString("zip"))
		withRecords := Must(cmd.Flags().GetBool("withRecords"))
		withMessages := Must(cmd.Flags().GetBool("withMessages"))

		if out != "json" {
			if cmd.Flag("withRecords").Changed {
				panic("Cannot use 'withRecords' when output format is not 'json'")
			}
			if cmd.Flag("withMessages").Changed {
				panic("Cannot use 'withMessages' when output format is not 'json'")
			}
		}

		zipAlgo, compression, err := serialization.ParseZip(zip)
		if err != nil {
			panic(err)
		}

		resultFilters := make([]FilterPredicate[resolver.Result], 0)
		if cmd.Flag("domain").Changed {
			domains := Must(cmd.Flags().GetStringSlice("domain"))
			resultFilters = append(resultFilters, DomainFilter(domains))
		}

		reader := getFilteredReaderZip(in, from, false, nil, 5*time.Minute, resultFilters...)

		var writer io.Writer
		if out != "" {
			out, closeFn, err := getZipFileWriter(out, zipAlgo, compression)
			if err != nil {
				panic(err)
			}
			defer closeFn()
			writer = out
		} else {
			out := bufio.NewWriter(os.Stdout)
			writer = out
			defer out.Flush()
		}

		c := make(chan resolver.Result)
		go func() {
			if err := reader.ReadTo(c); err != nil {
				panic(err)
			}
		}()

		for result := range c {
			if to == "protobuf" {
				err := protobuf.SerializeResult(result, writer, protobuf.ToMessage)
				if err != nil {
					panic(err)
				}
			} else if to == "json" {
				err := json.SerializeResult(result, writer, withRecords, withMessages)
				if err != nil {
					panic(err)
				}
			} else {
				panic(fmt.Sprintf("unknown output format: %v", to))
			}
		}
	},
}

func init() {
	rootCmd.AddCommand(ConvertFormat)

	ConvertFormat.Flags().String("in", "", "Path to the input file(s). Can be a glob pattern.")
	ConvertFormat.Flags().String("out", "", "File to write the output to. If empty, writes to stdout.")
	ConvertFormat.Flags().String("from", "protobuf", "Input format. Can be 'json' or 'protobuf'. Default is 'protobuf'.")
	ConvertFormat.Flags().String("to", "json", "Output format. Can be 'json' or 'protobuf'. Default is 'json'.")
	ConvertFormat.Flags().Bool("withRecords", false, "JSON only: Writes the resource records into the zone. IMPORTANT: this writes **ALL** RRSets served by the zone name servers into the zone, not just the ones that belong into the zone.")
	ConvertFormat.Flags().Bool("withMessages", true, "JSON only: Whether to include the message exchanges in the output.")
	ConvertFormat.Flags().StringSlice("domain", []string{}, "If provided, output will only contain the resolutions for the specified domain(s).")
	ConvertFormat.Flags().String("zip", "", "Zip algorithm and compression level to use for the output. Examples: zstd, zstd:best, zstd:fast, gzip, gzip:fast")

}
