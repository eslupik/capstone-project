package protobuf

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/DNS-MSMT-INET/yodns/resolver"
	"github.com/DNS-MSMT-INET/yodns/resolver/common"
	"github.com/DNS-MSMT-INET/yodns/resolver/model"
	"github.com/DNS-MSMT-INET/yodns/resolver/serialization"
	"golang.org/x/sync/errgroup"
	"google.golang.org/protobuf/proto"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const maxMessageSize = 64 * 1024 * 1024

type Reader struct {
	// Each function opens a file/stream that is to be parsed and returns
	// a reader for reading the file/stream, a function for closing the reader
	// and an error in case the reader could not be opened.
	streamFactory []func() (io.Reader, func() error, error)

	perFileTimeout time.Duration

	// If provided, sets the format of the files to read.
	// If nil, the format is auto-detected from the file extension.
	Zip *serialization.ZipAlgorithm

	// Allows customizing the conversion of the protobuf message to the model.MessageExchange
	MessageConverter func(exchange *MessageExchange) (model.MessageExchange, error)
}

func NewFileReader(filePattern string) (*Reader, error) {
	return NewFileReaderTimeout(filePattern, 0)
}

func NewFileReaderTimeout(filePattern string, timeout time.Duration) (*Reader, error) {
	r := &Reader{
		perFileTimeout: timeout,
		MessageConverter: func(exchange *MessageExchange) (model.MessageExchange, error) {
			return exchange.ToModel()
		},
	}

	matches, err := filepath.Glob(filePattern)
	if err != nil {
		return r, err
	}
	r.streamFactory = make([]func() (io.Reader, func() error, error), 0, len(matches))

	for _, m := range matches {
		match := m

		fileInfo, err := os.Stat(match)
		if err == nil && fileInfo.IsDir() {
			continue
		}

		r.streamFactory = append(r.streamFactory, func() (io.Reader, func() error, error) {
			zip := serialization.GetZipAlgoFromExtensions(match)
			if r.Zip != nil {
				zip = *r.Zip
			}
			inputReader, closeReader, err := serialization.OpenReader(match, zip)
			return inputReader, closeReader, err
		})
	}

	return r, nil
}

// NewStreamReaderTimeout returns a new Reader that reads from the given input stream.
func NewStreamReaderTimeout(input io.Reader, timeout time.Duration) *Reader {
	return &Reader{
		perFileTimeout: timeout,
		MessageConverter: func(exchange *MessageExchange) (model.MessageExchange, error) {
			return exchange.ToModel()
		},
		streamFactory: []func() (io.Reader, func() error, error){
			func() (io.Reader, func() error, error) {
				return input, func() error { return nil }, nil
			},
		},
	}
}

func (j *Reader) ReadTo(outChan chan<- resolver.Result) error {
	defer func() {
		close(outChan)
	}()

	for _, inputInit := range j.streamFactory {
		inputReader, closeReader, err := inputInit()
		if err != nil {
			return err
		}

		ctx := context.Background()
		cncl := func() {}
		if j.perFileTimeout > 0 {
			ctx, cncl = context.WithTimeout(context.Background(), j.perFileTimeout)
		}

		err = ReadAllMessages(ctx, inputReader, j.MessageConverter, outChan)
		cncl()

		closeReader()
		if err != nil {
			return err
		}
	}

	return nil
}

// ReadAllMessages reads all results from the reader and posts them to the out channel
func ReadAllMessages(ctx context.Context,
	reader io.Reader,
	messageConverter func(*MessageExchange) (model.MessageExchange, error),
	outChan chan<- resolver.Result) error {
	for {
		var msgCount uint64
		if err := binary.Read(reader, binary.BigEndian, &msgCount); errors.Is(err, io.EOF) {
			return nil
		} else if err != nil {
			return err
		}

		// Read the first message (the 'WriteModel', containing the zones and nameservers)
		var firstMessage Resolution
		if bytes, err := readNextMessageBytes(reader); err == io.EOF {
			return nil
		} else if err != nil {
			return err
		} else if err := proto.Unmarshal(bytes, &firstMessage); err != nil {
			return err
		}

		var nsMapMu sync.Mutex
		writeModel := FromWriteModel(&firstMessage)

		// Start a worker that will unmarshal all subsequent messages (the 'MessageExchange' messages)
		// We use a worker to decouple reading the byte stream from unmarshalling for better performance
		msgBytes := make(chan []byte, 100)
		g, ctx := errgroup.WithContext(ctx)
		g.SetLimit(5)
		g.Go(func() error {
			for {
				select {
				case <-ctx.Done():
					return ctx.Err()
				case b, ok := <-msgBytes:
					if !ok { // Channel closed
						return nil
					}

					var protoMsg MessageExchange
					if err := proto.Unmarshal(b, &protoMsg); err != nil {
						return err
					}

					if msgExchange, err := messageConverter(&protoMsg); err == nil {
						nsMapMu.Lock()
						writeModel.Msgs.AppendMessage(msgExchange)
						nsMapMu.Unlock()
					} else {
						return err
					}
				}
			}
		})

		// Start reading the input stream message by message
		for i := 1; i < int(msgCount); i++ {
			select {
			case <-ctx.Done():
				break
			default:
				if bytes, err := readNextMessageBytes(reader); err != nil {
					close(msgBytes)
					return err
				} else {
					msgBytes <- bytes // Enqueue for deserialization
				}
			}

		}

		close(msgBytes) // Signal the worker(s)
		if err := g.Wait(); err != nil {
			return err
		}

		outChan <- writeModel
	}
}

func readNextMessageBytes(reader io.Reader) ([]byte, error) {
	var msgLen uint64
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

func FromWriteModel(out *Resolution) resolver.Result {
	r := resolver.Result{
		Domains:   make([]resolver.TaggedDomainName, 0, len(out.Domains)),
		Duration:  time.Duration(out.Duration),
		StartTime: out.StartTime.AsTime(),
		Zone:      fromZone(out.ZoneData, make(map[model.DomainName]*model.NameServer)),
		Msgs:      model.NewMessageIdx(),
	}

	for i, dn := range out.Domains {
		r.Domains = append(r.Domains, resolver.TaggedDomainName{
			Name: model.DomainName(dn),
			Tags: out.Tags[i],
			Idx:  uint(out.Idx[i]),
		})
	}

	return r
}

func fromZone(zone *Zone, nameservers map[model.DomainName]*model.NameServer) *model.Zone {
	result := &model.Zone{
		Name: model.MustNewDomainName(zone.Name),
	}

	for _, protoNs := range zone.NameServers {
		if ns, exists := nameservers[model.MustNewDomainName(protoNs.Name)]; exists {
			result.NameServers = append(result.NameServers, ns)
		} else {
			ns = fromNameServer(protoNs)
			nameservers[model.MustNewDomainName(protoNs.Name)] = ns
			result.NameServers = append(result.NameServers, ns)
		}
	}

	for _, sz := range zone.SubZones {
		modelSz := fromZone(sz, nameservers)
		modelSz.Parent = result
		result.Subzones = append(result.Subzones, modelSz)
	}

	return result
}

func fromNameServer(ns *NameServer) *model.NameServer {
	return &model.NameServer{
		Name:        model.MustNewDomainName(ns.Name),
		IPAddresses: fromIPAddresses(ns.IpAddresses),
	}
}

func fromIPAddresses(ipAddrs []string) common.CompSet[netip.Addr] {
	result := common.NewCompSet[netip.Addr]()
	for _, ip := range ipAddrs {
		result.Add(netip.MustParseAddr(ip))
	}
	return result
}
