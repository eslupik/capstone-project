package cmd

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"github.com/mailru/easyjson"
	"github.com/miekg/dns"
	"github.com/spf13/cobra"
	"github.com/DNS-MSMT-INET/yodns/resolver/model"
	"github.com/DNS-MSMT-INET/yodns/resolver/serialization/json"
	"github.com/DNS-MSMT-INET/yodns/resolver/serialization/protobuf"
	"google.golang.org/protobuf/proto"
	"io"
	"net/netip"
	"os"
	"time"
)

var ReadMessagesBinary = &cobra.Command{
	Use:   "readMessagesBinary",
	Short: "Reads files created by extractMessagesBinary and streams the output to json.",
	Run: func(cmd *cobra.Command, args []string) {
		in := Must(cmd.Flags().GetString("in"))

		reader, closeFunc, err := getFileReader(in)
		if err != nil {
			panic(fmt.Errorf("%v: %w", in, err))
		}
		defer closeFunc()

		out := bufio.NewWriter(os.Stdout)
		defer out.Flush()

		for {
			var protoMsg protobuf.MessageExchange
			if b, err := readNextMsg(reader); err == io.EOF {
				break
			} else if err != nil {
				panic(fmt.Errorf("%v: %w", in, err))
			} else if err := proto.Unmarshal(b, &protoMsg); err != nil {
				panic(fmt.Errorf("%v: %w", in, err))
			}

			modelMsg, err := toModel(&protoMsg)
			if err != nil {
				panic(fmt.Errorf("%v: %w", in, err))
			}
			jsonModel := json.From(&modelMsg)
			jsonModel.Message.OriginalBytes = ""
			jsonBytes, err := easyjson.Marshal(jsonModel)
			if err != nil {
				panic(fmt.Errorf("%v: %w", in, err))
			}

			if _, err := out.Write(jsonBytes); err != nil {
				panic(fmt.Errorf("%v: %w", in, err))
			}
			if _, err := out.Write([]byte("\n")); err != nil {
				panic(fmt.Errorf("%v: %w", in, err))
			}
		}
	},
}

func readNextMsg(reader io.Reader) ([]byte, error) {
	var msgLen uint32
	if err := binary.Read(reader, binary.BigEndian, &msgLen); err != nil {
		return nil, err
	}

	// arbitrary size, but above almost certainly means the message is not valid
	if msgLen > maxMessageSize {
		return nil, fmt.Errorf("message too large")
	}

	bytes := make([]byte, msgLen)
	if _, err := io.ReadFull(reader, bytes); err != nil {
		return nil, err
	}

	return bytes, nil
}

// Same as protobuf.MessageExchange.ToModel() but this method does not attempt to parse fields that are omitted by extractMessagesBinary.
func toModel(msg *protobuf.MessageExchange) (model.MessageExchange, error) {
	result := model.MessageExchange{
		OriginalQuestion: model.Question{
			Name:  model.MustNewDomainName(msg.OriginalQuestion.Name),
			Type:  uint16(msg.OriginalQuestion.Type),
			Class: uint16(msg.OriginalQuestion.Class),
		},
		ResponseAddr: msg.ResponseAddr,
		NameServerIP: netip.MustParseAddr(msg.NameServerIp),
		Metadata: model.Metadata{
			FromCache:   msg.Metadata.FromCache,
			RetryIdx:    uint(msg.Metadata.RetryIdx),
			TCP:         msg.Metadata.Tcp,
			DequeueTime: msg.Metadata.DequeueTime.AsTime(),
			IsFinal:     msg.Metadata.IsFinal,
			RTT:         time.Duration(msg.Metadata.Rtt),
		},
	}

	if len(msg.Message) > 0 {
		result.Message = new(dns.Msg)
		_ = result.Message.Unpack(msg.Message) // ignore the error (malformed messages may appear)
	}

	if msg.ErrorCode != "" || msg.ErrorMessage != "" {
		result.Error = &model.SendError{
			Message: msg.ErrorMessage,
			Code:    model.ErrorCode(msg.ErrorCode),
		}
	}

	return result, nil
}

func init() {
	rootCmd.AddCommand(ReadMessagesBinary)

	ReadMessagesBinary.Flags().String("in", "", "")
}
