package cmd

import (
	"encoding/binary"
	"fmt"
	"github.com/DNS-MSMT-INET/yodns/resolver"
	"github.com/DNS-MSMT-INET/yodns/resolver/model"
	"github.com/DNS-MSMT-INET/yodns/resolver/serialization"
	"github.com/DNS-MSMT-INET/yodns/resolver/serialization/protobuf"
	"github.com/spf13/cobra"
	"google.golang.org/protobuf/proto"
	"io"
	"net/netip"
	"os"
	"path"
	"time"
)

var ExtractMessagesBinary = &cobra.Command{
	Use:   "extractMessagesBinary",
	Short: "Extracts and filter messages from a given input file.",
	Long:  "Extracts and filter messages from a given input file.",
	Args: func(cmd *cobra.Command, args []string) error {
		format, _ := cmd.Flags().GetString("format")
		if format != "json" && format != "protobuf" {
			return fmt.Errorf("format must be either 'json' or 'protobuf'")
		}
		return nil
	},
	Run: func(cmd *cobra.Command, args []string) {
		in := Must(cmd.Flags().GetString("in"))
		out := Must(cmd.Flags().GetString("out"))
		format, _ := cmd.Flags().GetString("format")
		zip := Must(cmd.Flags().GetString("zip"))

		if err := os.MkdirAll(path.Dir(out), os.ModePerm); err != nil {
			panic(err)
		}

		zipAlgo, compression, err := serialization.ParseZip(zip)
		if err != nil {
			panic(err)
		}

		outWriter, closeFunc, err := getZipFileWriter(out, zipAlgo, compression)
		if err != nil {
			panic(err)
		}
		defer closeFunc()

		c := make(chan resolver.Result, 200)
		reader := getFilteredReaderZip(in, format, false, nil, 5*time.Minute)
		go func() {
			if err := reader.ReadTo(c); err != nil {
				panic(fmt.Errorf("%v %w", out, err))
			}
		}()

		for p := range c {
			domainDict := make(map[model.DomainName]any)
			for _, domain := range p.Domains {
				domainDict[domain.Name] = nil
			}

			nsIPDict := make(map[netip.Addr][]model.DomainName)
			for _, ns := range p.Zone.GetNameServersRecursive() {
				for _, ip := range ns.IPAddresses.Items() {
					nsIPDict[ip] = append(nsIPDict[ip], ns.Name)
				}
			}

			for iter := p.Msgs.Iterate(); iter.HasNext(); {
				msg := iter.Next()

				if msg.Metadata.FromCache {
					continue
				}

				var protoMsg protobuf.MessageExchange
				err = protoMsg.From(msg)
				if err != nil {
					panic(fmt.Errorf("%v %w", in, err))
				}

				protoMsg.Metadata.ConnId = nil
				protoMsg.Metadata.ParentId = nil
				protoMsg.Metadata.CorrelationId = nil
				protoMsg.Metadata.EnqueueTime = nil

				if err := writeMsg(&protoMsg, outWriter); err != nil {
					panic(fmt.Errorf("%v %w", in, err))
				}
			}
		}
	},
}

func writeMsg(msg proto.Message, writer io.Writer) error {
	msgBytes, err := proto.Marshal(msg)
	if err != nil {
		return err
	}

	// First, put the length of the message
	lenBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(lenBytes, uint32(len(msgBytes)))
	if _, err = writer.Write(lenBytes); err != nil {
		return err
	}

	// Then put the actual message
	if _, err = writer.Write(msgBytes); err != nil {
		return err
	}

	return nil
}

func init() {
	rootCmd.AddCommand(ExtractMessagesBinary)

	ExtractMessagesBinary.Flags().String("in", "", "")
	ExtractMessagesBinary.Flags().String("out", "messages.json", "")
	ExtractMessagesBinary.Flags().String("format", "protobuf", "")
	ExtractMessagesBinary.Flags().String("zip", "zst:best", "")
}
