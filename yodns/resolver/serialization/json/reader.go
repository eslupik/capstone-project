package json

import (
	"bufio"
	"context"
	"encoding/base64"
	"github.com/mailru/easyjson"
	"github.com/miekg/dns"
	"github.com/DNS-MSMT-INET/yodns/resolver"
	"github.com/DNS-MSMT-INET/yodns/resolver/common"
	"github.com/DNS-MSMT-INET/yodns/resolver/model"
	"github.com/DNS-MSMT-INET/yodns/resolver/serialization"
	"golang.org/x/sync/errgroup"
	"path/filepath"
)

type Reader struct {
	filePattern string
	parallel    bool

	// If provided, sets the format of the files to read.
	// If nil, the format is auto-detected from the file extension.
	Zip *serialization.ZipAlgorithm
}

func NewReader(filePattern string, parallel bool) Reader {
	return Reader{
		filePattern: filePattern,
		parallel:    parallel,
	}
}

func (j Reader) ReadTo(outChan chan<- resolver.Result) error {
	matches, err := filepath.Glob(j.filePattern)
	if err != nil {
		panic(err)
	}

	g, _ := errgroup.WithContext(context.Background())
	if !j.parallel {
		g.SetLimit(1)
	}

	for _, match := range matches {
		g.Go(func() error {
			zip := serialization.GetZipAlgoFromExtensions(match)
			if j.Zip != nil {
				zip = *j.Zip
			}

			return readFile(match, zip, outChan)
		})
	}

	result := g.Wait()
	close(outChan)
	return result
}

// readFile reads a collector file line by line and posts the line into the
// outChan where some other process can do analysis, aggregation, etc.
func readFile(inputFilePath string, zip serialization.ZipAlgorithm, outChan chan<- resolver.Result) error {
	inputFile, closeFile, err := serialization.OpenReader(inputFilePath, zip)
	if err != nil {
		return err
	}
	defer closeFile()

	inputScanner := bufio.NewScanner(inputFile)

	// Increase buffer capacity because lines can be pretty long (default is 64KB)
	const maxCapacity = 32 * 1024 * 1024
	buf := make([]byte, maxCapacity)
	inputScanner.Buffer(buf, maxCapacity)

	for inputScanner.Scan() {
		var data WriteModel

		if err = easyjson.Unmarshal(inputScanner.Bytes(), &data); err != nil {
			return err // For example buffer to small to read the line
		}

		outChan <- data.toResult()
	}

	return inputScanner.Err()
}

func (out *WriteModel) toResult() resolver.Result {
	r := resolver.Result{
		Duration:  out.Duration,
		StartTime: out.StartTime,
		Zone:      toModelZone(out.Zonedata, make(map[model.DomainName]*model.NameServer)),
		Msgs:      toModelMessagesExchanges(out.Messages),
	}

	for _, dn := range out.Domains {
		r.Domains = append(r.Domains, resolver.TaggedDomainName{
			Name: dn.Name,
			Tags: dn.Tags,
			Idx:  dn.Idx,
		})
	}

	return r
}

func toModelZone(zone Zone, nameservers map[model.DomainName]*model.NameServer) *model.Zone {
	result := &model.Zone{
		Name:        model.MustNewDomainName(zone.Name),
		Subzones:    []*model.Zone{},
		NameServers: []*model.NameServer{},
	}

	for _, sz := range zone.Subzones {
		modelSz := toModelZone(sz, nameservers)
		modelSz.Parent = result
		result.Subzones = append(result.Subzones, modelSz)
	}

	for _, ns := range zone.NameServers {
		if modelNs, ok := nameservers[model.MustNewDomainName(ns.Name)]; ok {
			result.NameServers = append(result.NameServers, modelNs)
		} else {
			modelNs = toModelNameServer(ns)
			nameservers[model.MustNewDomainName(ns.Name)] = modelNs
			result.NameServers = append(result.NameServers, modelNs)
		}
	}

	return result
}

func toModelNameServer(ns NameServer) *model.NameServer {
	return &model.NameServer{
		Name:        model.MustNewDomainName(ns.Name),
		IPAddresses: common.NewCompSet(ns.IPAddresses...),
	}
}

func toModelMessagesExchanges(msgExs []MessageExchange) *model.MsgIdx {
	result := model.NewMessageIdx()

	for _, msgEx := range msgExs {
		modelMsg := model.MessageExchange{
			OriginalQuestion: msgEx.OriginalQuestion,
			ResponseAddr:     msgEx.ResponseAddr,
			NameServerIP:     msgEx.NameServerIP,
			Metadata:         msgEx.Metadata,
			Error:            msgEx.Error,
		}

		if msgEx.Message != nil && msgEx.Message.OriginalBytes != "" {
			modelMsg.Message = new(dns.Msg)
			bytes, err := base64.StdEncoding.DecodeString(msgEx.Message.OriginalBytes)
			if err != nil {
				panic(err)
			}

			err = modelMsg.Message.Unpack(bytes)
			if err != nil {
				panic(err)
			}
		}

		result.AppendMessage(modelMsg)

	}

	return result
}
