package protobuf

import (
	"encoding/binary"
	"github.com/DNS-MSMT-INET/yodns/resolver"
	"github.com/DNS-MSMT-INET/yodns/resolver/common"
	"github.com/DNS-MSMT-INET/yodns/resolver/model"
	"github.com/DNS-MSMT-INET/yodns/resolver/serialization"
	"golang.org/x/sync/errgroup"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
	"io"
	"net/netip"
)

type Writer struct {
	*serialization.FileWriterBase
	writeGroup errgroup.Group

	// Allows customizing the conversion of model.MessageExchange to a protobuf message
	MessageConverter func(exchange *model.MessageExchange) (*MessageExchange, error)
}

func NewWriter(outDir string, filePrefix string, outputFileSize uint, zipAlgo serialization.ZipAlgorithm, compression serialization.CompressionLevel, parallelFiles uint32) *Writer {
	w := &Writer{
		FileWriterBase:   serialization.NewFileWriterBase(outDir, filePrefix, "pb", outputFileSize, parallelFiles, true, zipAlgo, compression),
		MessageConverter: ToMessage,
	}

	// These are the numbers of deserialization workers
	// Important to bound their number, else they might fill the RAM
	// if the data is not written fast enough.
	w.writeGroup.SetLimit(500)
	return w
}

// WriteAsync enqueues the writing of the result and returns immediately
// WriteAsync deploys a custom protobuf format (see below). We use the format for two reasons:
//
// 1) we want to write multiple results into the same file, so we need to keep track when a message ends,
// as protobuf is not self-delimiting ((https://protobuf.dev/programming-guides/techniques/#streaming))
//
// 2) Although, protobuf supports large messages in theory, many implementations face issues for very large messages.
// The golang implementation seems to have no problem, but there is no current python implementation that can parse multi-GB messages.
// Therefore, we split the result into smaller messages that can be serialized independently and then recombined.
//
// The first message is always of type WriteModel. Subsequent messages are of type MessageExchange:
// The format is as follows:
//
//	                                                      +-------------------------------------------+
//		                                                  | REPEATED for number of messages           |
//		+-------------------------------------------------+----------------------------+--------------+
//		|                     8 Bytes                     |          8 Bytes           |   x Bytes    |
//		+-------------------------------------------------+----------------------------+--------------+
//		| Count of proto messages that follow (BigEndian) | Length of the next message | Message Body |
//		+-------------------------------------------------+----------------------------+--------------+
func (j *Writer) WriteAsync(result resolver.Result) (rtnErr error) {
	j.writeGroup.Go(func() error {
		writer, err := j.GetWriter()
		if err != nil {
			return err
		}

		defer func() {
			if err := writer.Close(); err != nil {
				rtnErr = common.ChainErr(rtnErr, err)
			}
		}()

		return SerializeResult(result, writer, j.MessageConverter)
	})

	return nil
}

func SerializeResult(result resolver.Result,
	writer io.Writer,
	convertMessage func(exchange *model.MessageExchange) (*MessageExchange, error)) error {
	out := new(Resolution)
	out.StartTime = timestamppb.New(result.StartTime)
	out.Duration = int64(result.Duration)
	out.ZoneData = ToZone(result.Zone)
	out.Domains = make([]string, 0, len(result.Domains))
	out.Tags = make([]string, 0, len(result.Domains))
	out.Idx = make([]uint64, 0, len(result.Domains))

	for _, dn := range result.Domains {
		out.Domains = append(out.Domains, string(dn.Name))
		out.Tags = append(out.Tags, dn.Tags)
		out.Idx = append(out.Idx, uint64(dn.Idx))
	}

	// "If you want to write multiple messages to a single file or stream, it is up to you to keep track of where one message ends and the next begins.
	// The Protocol Buffer wire format is not self-delimiting, so protocol buffer parsers cannot determine where a message ends on their own.
	// The easiest way to solve this problem is to write the size of each message before you write the message itself."

	// Write the total count of messages
	lenBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(lenBytes, uint64(result.Msgs.Count()+1))
	if _, err := writer.Write(lenBytes); err != nil {
		return err
	}

	// Write each individual message
	if err := writeMsg(out, lenBytes, writer); err != nil {
		return err
	}
	for iter := result.Msgs.Iterate(); iter.HasNext(); {
		msg := iter.Next()
		protoMsg, err := convertMessage(msg)
		if err != nil {
			return err
		}

		if err := writeMsg(protoMsg, lenBytes, writer); err != nil {
			return err
		}
	}

	return nil
}

func writeMsg(msg proto.Message, lenBytes []byte, writer io.Writer) error {
	msgBytes, err := proto.Marshal(msg)
	if err != nil {
		return err
	}

	// First, put the length of the message
	binary.BigEndian.PutUint64(lenBytes, uint64(len(msgBytes)))
	if _, err = writer.Write(lenBytes); err != nil {
		return err
	}

	// Then put the actual message
	if _, err = writer.Write(msgBytes); err != nil {
		return err
	}

	return nil
}

func (j *Writer) Wait() error {
	err := j.writeGroup.Wait()
	_ = j.CloseAll() // writeGroup workers should have closed the files already - remove or keep to make sure the writers are flushed in any case?
	return err
}

func toNameServers(servers []*model.NameServer) []*NameServer {
	var result = make([]*NameServer, len(servers))

	for i, ns := range servers {
		result[i] = &NameServer{
			Name:        string(ns.Name),
			IpAddresses: toIPs(ns.IPAddresses),
		}
	}
	return result
}

func toIPs(ipsSet common.CompSet[netip.Addr]) []string {
	ips := ipsSet.Items()
	result := make([]string, len(ips))

	for i, ip := range ips {
		result[i] = ip.String()
	}
	return result
}

func ToMessage(exchange *model.MessageExchange) (*MessageExchange, error) {
	result := new(MessageExchange)
	err := result.From(exchange)
	return result, err
}

func ToZone(modelZone *model.Zone) *Zone {
	var subzones []*Zone
	for _, sz := range modelZone.Subzones {
		subzones = append(subzones, ToZone(sz))
	}

	return &Zone{
		Name:        string(modelZone.Name),
		SubZones:    subzones,
		NameServers: toNameServers(modelZone.NameServers),
	}
}
