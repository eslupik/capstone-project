package json

import (
	"github.com/DNS-MSMT-INET/yodns/resolver"
	"github.com/DNS-MSMT-INET/yodns/resolver/common"
	"github.com/DNS-MSMT-INET/yodns/resolver/model"
	"github.com/DNS-MSMT-INET/yodns/resolver/serialization"
	"github.com/mailru/easyjson"
	"golang.org/x/sync/errgroup"
	"io"
	"sort"
)

type Writer struct {
	*serialization.FileWriterBase
	writeRecordsToZone bool
	writeGroup         errgroup.Group
}

func NewWriter(outDir string, filePrefix string, outputFileSize uint, zipAlgo serialization.ZipAlgorithm, compression serialization.CompressionLevel, parallelFiles uint32) *Writer {
	return &Writer{
		FileWriterBase:     serialization.NewFileWriterBase(outDir, filePrefix, "json", outputFileSize, parallelFiles, true, zipAlgo, compression),
		writeRecordsToZone: false,
	}
}

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

		return SerializeResult(result, writer, j.writeRecordsToZone, true)
	})

	return nil
}

func SerializeResult(result resolver.Result,
	writer io.Writer,
	writeRecordsToZone bool,
	writeMessages bool) error {

	out := WriteModel{}
	out.fromResult(result, writeRecordsToZone, writeMessages)

	bytes, err := easyjson.Marshal(&out)
	if err != nil {
		return err
	}

	if _, err = writer.Write(bytes); err != nil {
		return err
	}
	if _, err = writer.Write([]byte("\n")); err != nil {
		return err
	}

	return nil
}

func (j *Writer) Wait() error {
	err := j.writeGroup.Wait()
	_ = j.CloseAll() // writeGroup workers should have closed the files already - remove or keep to make sure the writers are flushed in any case?
	return err
}

func (out *WriteModel) fromResult(result resolver.Result, addRecords bool, addMessages bool) {
	for _, dn := range result.Domains {
		out.Domains = append(out.Domains, TaggedDomain{
			Name: dn.Name,
			Tags: dn.Tags,
			Idx:  dn.Idx,
		})
	}

	out.StartTime = result.StartTime
	out.Duration = result.Duration
	out.Zonedata = toZone(result.Zone, result.Msgs, addRecords)

	if addMessages {
		out.Messages = toMessageExchanges(result.Msgs)
	}
}

func toNameServers(modelNses []*model.NameServer) []NameServer {
	records := make([]NameServer, len(modelNses))
	for i, modelNs := range modelNses {
		records[i] = NameServer{
			Name:        string(modelNs.Name),
			IPAddresses: modelNs.IPAddresses.Items(),
		}
	}

	return records
}

func toZone(modelZone *model.Zone, msgs *model.MsgIdx, addRecords bool) Zone {
	var subzones []Zone
	for _, sz := range modelZone.Subzones {
		subzones = append(subzones, toZone(sz, msgs, addRecords))
	}

	var records []string
	if addRecords {
		rrs := modelZone.GetRecords(msgs)
		sort.SliceStable(rrs, func(i, j int) bool {
			return rrs[i].Header().Name > rrs[j].Header().Name
		})
		for _, rr := range rrs {
			records = append(records, rr.String())
		}
	}

	return Zone{
		Name:            string(modelZone.Name),
		ResourceRecords: records,
		Subzones:        subzones,
		NameServers:     toNameServers(modelZone.NameServers),
	}
}

func toMessageExchanges(msgs *model.MsgIdx) []MessageExchange {
	result := make([]MessageExchange, msgs.Count())
	iter := msgs.Iterate()
	for i := 0; iter.HasNext(); i++ {
		msg := iter.Next()
		result[i] = From(msg)
	}
	return result
}
