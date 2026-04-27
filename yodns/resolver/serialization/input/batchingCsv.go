package input

import (
	"encoding/csv"
	"fmt"
	"github.com/rs/zerolog"
	"github.com/DNS-MSMT-INET/yodns/resolver/common"
	"github.com/DNS-MSMT-INET/yodns/resolver/model"
	"io"
	"strings"
)

const (
	InputBufferSize = 32 * 1024
)

type BatchingCSV struct {
	FilePath       string
	CsvColumnIndex int
	TagColumnIndex int
	Separator      rune
	Offset         uint
	Len            uint
	Log            zerolog.Logger
	BatchSize      uint
	Psl            *model.PSL
}

var openCSVReader = func(filePath string, separator rune) (*csv.Reader, func() error, error) {
	var f io.Reader
	var closeFunc = func() error { return nil }
	var err error

	// If filePath is empty, read from stdin
	if filePath == "" {
		f = getStdInReader(InputBufferSize)
	} else {
		f, closeFunc, err = getFileReader(filePath, InputBufferSize)
	}

	if err != nil {
		return nil, nil, err
	}

	reader := csv.NewReader(f)
	reader.FieldsPerRecord = -1
	reader.ReuseRecord = true
	if separator != 0 {
		reader.Comma = separator
	}

	return reader, closeFunc, nil
}

func (in BatchingCSV) Read(ctx common.Context) <-chan []Item {
	// Apply the offset.
	inReader, closeFunc, err := openCSVReader(in.FilePath, in.Separator)
	if err != nil {
		in.Log.Panic().Err(err).
			Str("filePath", in.FilePath).
			Msg("Can not open input file")
	}

	if err = advanceToOffset(inReader, in.Offset); err != nil {
		in.Log.Panic().Err(err).
			Str("filePath", in.FilePath).
			Uint("offset", in.Offset).
			Msg("Can not apply offset")
	}

	in.Log.Info().
		Msgf("Reading records from %v. Starting at offset %v", in.FilePath, in.Offset)

	inputChan := make(chan []Item)

	idx := in.Offset
	ctx.Go(func() {
		defer closeFunc()
		defer close(inputChan)

		var recentBatch []Item
		var batchSLD model.DomainName

		submitBatch := func() {
			if len(recentBatch) == 0 {
				return
			}

			select {
			case <-ctx.Done():
				return
			case inputChan <- recentBatch:
				// nop
			}

			// start a new batch
			recentBatch = []Item{}
			batchSLD = ""
		}

		for i := uint(0); i < in.Len; i++ {
			record, err := inReader.Read()
			if err == io.EOF {
				return
			}
			if err != nil {
				panic(err)
			}

			dn, err := model.NewDomainName(strings.TrimSpace(record[in.CsvColumnIndex]))
			if err != nil {
				in.Log.Err(err).
					Str("domainName", record[in.CsvColumnIndex]).
					Msg("Invalid domain name")
				continue
			}

			sld := dn

			// Without a PSL, use the full domain name => Will result in no-batching
			if in.Psl != nil {
				sld, err = in.Psl.ToPLD(dn)
			}

			// Submit the batch if the SLD changed or cannot be determined
			if err != nil || sld != batchSLD {
				submitBatch()
				batchSLD = sld
			}

			// Add item to the recent batch
			recentBatch = append(recentBatch, Item{
				Idx:  idx,
				Name: dn,
				Tags: getTags(record, in.TagColumnIndex),
			})
			idx++

			// Submit the batch if it is full
			if len(recentBatch) == int(in.BatchSize) {
				submitBatch()
			}
		}

		// Submit the last batch, if something is left.
		submitBatch()
	})

	return inputChan
}

func getTags(row []string, tagColumnIndex int) string {
	if tagColumnIndex >= 0 && tagColumnIndex < len(row) {
		return row[tagColumnIndex]
	}
	return ""
}

func advanceToOffset(reader *csv.Reader, offset uint) error {
	for i := uint(0); i < offset; i++ {
		if _, err := reader.Read(); err != nil {
			return fmt.Errorf("error at line %v: %w", i, err)
		}
	}
	return nil
}
