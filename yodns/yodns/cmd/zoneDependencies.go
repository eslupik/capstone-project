package cmd

import (
	"fmt"
	"github.com/spf13/cobra"
	"github.com/DNS-MSMT-INET/yodns/resolver"
	"github.com/DNS-MSMT-INET/yodns/resolver/model"
	"github.com/DNS-MSMT-INET/yodns/resolver/serialization"
	"strings"
	"time"
)

var ZoneDependencies = &cobra.Command{
	Use:   "zoneDependencies",
	Short: "Extracts the dependencies for each zone and writes them to a CSV file.",
	Long: "Extracts the number of dependent zones for each zone and writes them to a CSV file. " +
		"A zone depends on itself, its parents and its name servers and all dependencies of parents and name servers recursively. ",
	Run: func(cmd *cobra.Command, args []string) {
		in := Must(cmd.Flags().GetString("in"))
		out := Must(cmd.Flags().GetString("out"))
		zip := Must(cmd.Flags().GetString("zip"))
		printHeader := Must(cmd.Flags().GetBool("print-header"))

		zipAlgo, compression, err := serialization.ParseZip(zip)
		if err != nil {
			panic(err)
		}

		// Unless format is explicitly set, try to infer it from the in-path
		format := Must(cmd.Flags().GetString("format"))
		if !cmd.Flag("format").Changed {
			format = Must(inferFormat(in))
		}

		c := make(chan resolver.Result, 20)
		reader := getFilteredReaderZip(in, format, false, nil, 5*time.Minute)
		writer, closeFunc, err := getZipFileWriter(out, zipAlgo, compression)
		if err != nil {
			panic(err)
		}
		defer closeFunc()

		// start reading the input file to channel c
		go func() {
			if err := reader.ReadTo(c); err != nil {
				panic(fmt.Errorf("%v %w", in, err))
			}
		}()

		if printHeader {
			if _, err := writer.Write([]byte(fmt.Sprintf("Zone,Count,Dependencies\n"))); err != nil {
				panic(err)
			}
		}

		// Iterate over results in the file
		for p := range c {
			for _, zone := range p.Zone.Flatten() {
				deps := make(map[model.DomainName]any)
				zone.AddZoneDependencies(deps)

				strDeps := make([]string, 0, len(deps))
				for k := range deps {
					strDeps = append(strDeps, string(k))
				}
				csvLine := []byte(fmt.Sprintf("%v,%v,%v\n", zone.Name, len(deps), strings.Join(strDeps, ";")))
				if _, err := writer.Write(csvLine); err != nil {
					panic(err)
				}
			}
		}
	},
}

func init() {
	rootCmd.AddCommand(ZoneDependencies)

	ZoneDependencies.Flags().String("in", "", "Input file.")
	ZoneDependencies.MarkFlagRequired("in")

	ZoneDependencies.Flags().String("out", "", "Output file.")
	ZoneDependencies.MarkFlagRequired("out")

	ZoneDependencies.Flags().String("zip", "", "Zip the output.")
	ZoneDependencies.Flags().String("format", "protobuf", "Input file format.")
	ZoneDependencies.Flags().Bool("print-header", true, "Whether to print the CSV header.")
}
