package cmd

import (
	"fmt"
	"github.com/DNS-MSMT-INET/yodns/resolver"
	"github.com/DNS-MSMT-INET/yodns/resolver/serialization"
	"github.com/DNS-MSMT-INET/yodns/resolver/serialization/protobuf"
	"github.com/spf13/cobra"
	"io"
	"os"
	"path"
	"strings"
	"time"
)

var ExtractDomains = &cobra.Command{
	Use:   "extractDomains",
	Short: "Extracts domains that match specified criteria to a separate file.",
	Run: func(cmd *cobra.Command, args []string) {
		in := Must(cmd.Flags().GetString("in"))
		out := Must(cmd.Flags().GetString("out"))
		format := Must(cmd.Flags().GetString("format"))
		tags := Must(cmd.Flags().GetStringSlice("tags"))

		tagsMap := make(map[string]any)
		for _, tag := range tags {
			tagsMap[tag] = nil
		}

		if err := os.MkdirAll(path.Dir(out), os.ModePerm); err != nil {
			panic(err)
		}

		var outWriter io.Writer

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
			extract := false
			for _, domain := range p.Domains {
				for _, tag := range tags {
					if strings.Contains(domain.Tags, tag) {
						extract = true
						break
					}
				}
			}

			if !extract {
				continue
			}

			if outWriter == nil {
				w, closeFunc, err := getZipFileWriter(out, serialization.ZipZSTD, serialization.CompressionBest)
				if err != nil {
					panic(err)
				}
				outWriter = w
				defer closeFunc()
			}

			if err := protobuf.SerializeResult(p, outWriter, protobuf.ToMessage); err != nil {
				panic(err)
			}
		}
	},
}

func init() {
	rootCmd.AddCommand(ExtractDomains)

	ExtractDomains.Flags().String("in", "", "Input file")
	ExtractDomains.Flags().String("out", "", "Output file")
	ExtractDomains.Flags().String("format", "protobuf", "File format. Protobuf or json.")
	ExtractDomains.Flags().StringSlice("tags", []string{"maj", "tra", "rad", "umb"}, "Tags to extract")
}
