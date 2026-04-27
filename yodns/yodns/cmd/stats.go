package cmd

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/spf13/cobra"
	"github.com/DNS-MSMT-INET/yodns/resolver"
	"github.com/DNS-MSMT-INET/yodns/resolver/common"
	"github.com/DNS-MSMT-INET/yodns/resolver/serialization"
	"github.com/DNS-MSMT-INET/yodns/resolver/serialization/protobuf"
	"golang.org/x/sync/errgroup"
	"google.golang.org/protobuf/proto"
	"io"
	"math"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const maxMessageSize = 64 * 1024 * 1024

type readResult struct {
	result   resolver.Result
	msgCount int
}

type stats struct {
	TotalDomains     int64
	TotalMsgs        int64
	TagCount         sync.Map
	TagCountNoRescan sync.Map
}

func (f *stats) MarshalJSON() ([]byte, error) {
	countByTag := make(map[string]int64)
	f.TagCount.Range(func(key, value any) bool {
		eRef := value.(*int64)
		countByTag[key.(string)] = *eRef
		return true
	})

	countByTagNoRescan := make(map[string]int64)
	f.TagCountNoRescan.Range(func(key, value any) bool {
		eRef := value.(*int64)
		countByTagNoRescan[key.(string)] = *eRef
		return true
	})

	return json.Marshal(&struct {
		TotalDomains       int64
		TotalMsgs          int64
		CountByTag         map[string]int64
		CountByTagNoRescan map[string]int64
	}{
		TotalDomains:       f.TotalDomains,
		TotalMsgs:          f.TotalMsgs,
		CountByTag:         countByTag,
		CountByTagNoRescan: countByTagNoRescan,
	})
}

var Stats = &cobra.Command{
	Use:   "stats",
	Short: "Calculates meta statistics for the dataset.",
	Long: "Sometimes domains have to be rescanned due to incidents that affect data quality, such as network outages. " +
		"Before publishing a dataset, we want to remove all potentially faulty domains from the files and store them separately. " +
		"Especially with regards to publishing a dataset this makes sense, as this is typically what is expected from a dataset. ",
	Run: func(cmd *cobra.Command, args []string) {
		ins := Must(cmd.Flags().GetStringSlice("in"))
		out := Must(cmd.Flags().GetString("out"))
		parallelism := Must(cmd.Flags().GetInt("parallelism"))
		skip := Must(cmd.Flags().GetInt("skip"))
		take := Must(cmd.Flags().GetInt("take"))

		if err := os.MkdirAll(path.Dir(out), os.ModePerm); err != nil {
			panic(err)
		}

		var files []string
		for _, in := range ins {
			moreFiles, err := filepath.Glob(in)
			if err != nil {
				panic(err)
			}
			files = append(files, moreFiles...)
		}

		slices.Sort(files)
		files = files[skip:common.MinInt(take, len(files))]

		readChan := make(chan readResult, 10*parallelism)

		agg := errgroup.Group{}
		g := errgroup.Group{}
		writegroup := errgroup.Group{}
		g.SetLimit(parallelism)
		start := time.Now()

		writeChan := make(chan []byte, 10*parallelism)
		writegroup.Go(func() error {
			outWriter(out, writeChan)
			return nil
		})

		s := new(stats)
		for i := 0; i < common.MaxInt(parallelism/30, 1); i++ {
			agg.Go(func() error {
				statAggregator(readChan, writeChan, s)
				return nil
			})
		}

		for i, file := range files {
			if i%1000 == 0 {
				fmt.Println(fmt.Sprintf("Processing file %v of %v. ETA: %v", i, len(files), start.Add(time.Duration(int(float64(time.Since(start))*float64(len(files))/float64(i+1))))))
			}

			f := file
			g.Go(func() error {
				return fileReader(f, readChan)
			})
		}

		if err := g.Wait(); err != nil {
			panic(err)
		}
		close(readChan)
		if err := agg.Wait(); err != nil {
			panic(err)
		}

		bytes, err := json.Marshal(s)
		if err != nil {
			panic(err)
		}

		writeChan <- bytes
		close(writeChan)
		if err := writegroup.Wait(); err != nil {
			panic(err)
		}
	},
}

func outWriter(out string, write chan []byte) {
	f, closeFn, err := getZipFileWriter(out, serialization.ZipZSTD, serialization.CompressionFast)
	if err != nil {
		panic(err)
	}
	//defer closeFn()

	for b := range write {
		if _, err := f.Write(b); err != nil {
			panic(err)
		}
	}

	time.Sleep(10 * time.Millisecond)
	closeFn()
}

func statAggregator(readTo <-chan readResult, writeTo chan<- []byte, s *stats) {
	for res := range readTo {
		atomic.AddInt64(&s.TotalDomains, int64(len(res.result.Domains)))
		atomic.AddInt64(&s.TotalMsgs, int64(res.msgCount))

		for _, dn := range res.result.Domains {
			tags := strings.Split(dn.Tags, ";")
			for _, tag := range tags {
				i := int64(0)
				e, _ := s.TagCount.LoadOrStore(tag, &i)
				eRef := e.(*int64)
				atomic.AddInt64(eRef, 1)
			}

			// Only for domains from original target list
			if dn.Idx != 0 {
				writeTo <- []byte(fmt.Sprintf("%v,%v,%v,%v,%v,%v\n", dn.Name, dn.Idx, dn.Tags, res.result.StartTime.Unix(), res.result.Duration.Seconds(), res.msgCount))
			}
		}
	}
}

func fileReader(file string, readTo chan<- readResult) error {
	f, closeFunc, err := getFileReader(file)
	if err != nil {
		return err
	}
	defer closeFunc()

	for true {
		r, msgs, err := readNext(f)
		readTo <- readResult{
			result:   r,
			msgCount: msgs - 1,
		}

		if errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			panic(err)
		}
	}

	return nil
}

// ReadAllMessages reads all results from the reader and posts them to the out channel
func readNext(reader io.Reader) (resolver.Result, int, error) {
	for {
		var msgCount uint64
		if err := binary.Read(reader, binary.BigEndian, &msgCount); errors.Is(err, io.EOF) {
			return resolver.Result{}, 0, err
		} else if err != nil {
			return resolver.Result{}, 0, err
		}

		// Read the first message (the 'WriteModel', containing the zones and nameservers)
		var firstMessage protobuf.Resolution
		if bytes, err := readNextMessageBytes(reader); err == io.EOF {
			return resolver.Result{}, 0, err
		} else if err != nil {
			return resolver.Result{}, 0, err
		} else if err = proto.Unmarshal(bytes, &firstMessage); err != nil {
			return resolver.Result{}, 0, err
		}

		writeModel := protobuf.FromWriteModel(&firstMessage)

		// Start a worker that will unmarshal all subsequent messages (the 'MessageExchange' messages)
		// We use a worker to decouple reading the byte stream from unmarshalling for better performance
		// Advance the cursor
		for i := 1; i < int(msgCount); i++ {
			if _, err := readNextMessageBytes(reader); err != nil {
				return writeModel, int(msgCount), err
			}
		}

		return writeModel, int(msgCount), nil
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

func init() {
	rootCmd.AddCommand(Stats)

	Stats.Flags().StringSlice("in", []string{}, "Input file(s)")
	Stats.Flags().String("out", "", "Output file for the statistics")
	Stats.Flags().Int("skip", 0, "Number of files to skip.")
	Stats.Flags().Int("parallelism", 1, "Parallel files to read.")
	Stats.Flags().Int("take", math.MaxInt32, "Number of files to take.")
}
