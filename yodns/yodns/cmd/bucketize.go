package cmd

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"github.com/rs/zerolog"
	"github.com/spf13/cobra"
	"github.com/DNS-MSMT-INET/yodns/resolver/serialization"
	"golang.org/x/exp/slices"
	"golang.org/x/sync/errgroup"
	"hash/fnv"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
)

var bucketize = &cobra.Command{
	Use: "bucketize",
	Run: func(cmd *cobra.Command, args []string) {
		inPath := Must(cmd.Flags().GetString("in"))
		outFolder := Must(cmd.Flags().GetString("out"))
		nrBuckets := Must(cmd.Flags().GetInt("buckets"))
		hashKey := Must(cmd.Flags().GetString("key"))
		dedupKeys := Must(cmd.Flags().GetStringSlice("dedup-key"))
		maxMem := Must(cmd.Flags().GetInt64("maxMem"))
		cacheSize := Must(cmd.Flags().GetUint64("cacheSize"))

		if maxMem > 0 {
			maxMemBytes := maxMem * 1024 * 1024 * 1024
			debug.SetMemoryLimit(maxMemBytes)
		}

		logger := zerolog.New(os.Stderr).Level(zerolog.InfoLevel).With().Timestamp().Logger()
		writers, writersCtx := errgroup.WithContext(context.Background())
		bucketChans := make([]chan []byte, nrBuckets)
		for i := 0; i < nrBuckets; i++ {
			outChan := make(chan []byte, 10)
			bucketChans[i] = outChan
			name := filepath.Join(outFolder, fmt.Sprintf("bucket_%06d.json.zst", i))
			writers.Go(func() error {
				return bucketWriter(writersCtx, outChan, name)
			})
		}

		files, err := filepath.Glob(inPath)
		if err != nil {
			panic(err)
		}

		dedupMap := NewSyncMapCapacity[string, any](cacheSize)

		readers, readersCtx := errgroup.WithContext(context.Background())
		readers.SetLimit(500)
		for i, f := range files {
			file := f
			readers.Go(func() error {
				return filereader(readersCtx, file, hashKey, bucketChans, dedupKeys, dedupMap, logger)
			})

			if i%1000 == 0 {
				fmt.Println(fmt.Sprintf("Reading file %v", i))
			}
		}
		err = readers.Wait()
		if err != nil {
			panic(err)
		}

		for _, c := range bucketChans {
			close(c)
		}

		err = writers.Wait()
		if err != nil {
			panic(err)
		}
	},
}

func filereader(ctx context.Context, inPath string, hashKey string, buckets []chan []byte, dedupKeys []string, dedupMap *SyncMapCapacity[string, any], logger zerolog.Logger) error {
	logger = logger.With().Str("file", inPath).Logger()
	r, closeFunc, err := getFileReaderSize(inPath, 32*1024*1024)
	if err != nil {
		return err
	}
	defer closeFunc()

	// Use another buffered reader instead of scanner
	// https://stackoverflow.com/questions/21124327/how-to-read-a-text-file-line-by-line-in-go-when-some-lines-are-long-enough-to-ca
	b := bufio.NewReaderSize(r, 32*1024*1024)

	for readData, isPrefix, err := b.ReadLine(); err == nil; readData, isPrefix, err = b.ReadLine() {
		data := readData
		if isPrefix { // The line is too long to fit the buffer - read until we find the end of line
			// Copy the buffer because "the returned buffer is only valid until the next call to ReadLine."
			data = slices.Clone(readData)
			for isPrefix && err == nil {
				readData, isPrefix, err = b.ReadLine()
				data = append(data, slices.Clone(readData)...)
			}
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			var objmap map[string]json.RawMessage
			err := json.Unmarshal(data, &objmap)
			if err != nil {
				logger.Error().Err(err).Msgf("Error parsing json")
				continue
			}

			// If the result is a rescan, we do not want to deduplicate (because we then we do not know which will be chosen)
			if len(dedupKeys) > 0 && isDuplicate(objmap, dedupKeys, dedupMap, logger) {
				continue
			}

			var key any
			err = json.Unmarshal(objmap[hashKey], &key)
			if err != nil {
				logger.Error().Err(err).Msgf("Error extracting key")
				continue
			}

			h := fnv.New32a()
			h.Write([]byte(fmt.Sprintf("%v", key)))
			idx := h.Sum32() % uint32(len(buckets))

			buckets[idx] <- append(slices.Clone(data), "\n"...)
		}
	}

	return nil
}

func isDuplicate(objmap map[string]json.RawMessage, dedupKeys []string, dedupMap *SyncMapCapacity[string, any], logger zerolog.Logger) bool {
	var dedupKey strings.Builder
	for _, k := range dedupKeys {
		var value any
		err := json.Unmarshal(objmap[k], &value)
		if err != nil {
			logger.Error().Err(err).Msgf("Error extracting dedup key %v", k)
			return false
		}
		dedupKey.WriteString(fmt.Sprintf("%v", value))

		// If we find a "rescan" tag in the tags, add this to deduplication
		// We want to keep at least one rescanned - the dedup command will later
		// prefer rescanned results over the original ones.
		if k == "tags" {
			if strings.Contains(value.(string), TagRescan) {
				dedupKey.WriteString("_r")
			}
		}

	}

	_, loaded := dedupMap.LoadOrStore(dedupKey.String(), nil)
	return loaded
}

func bucketWriter(ctx context.Context, inChan chan []byte, outpath string) error {
	writer, closeFunc, err := getZipFileWriter(outpath, serialization.ZipZSTD, serialization.CompressionFast)

	if err != nil {
		return err
	}
	defer closeFunc()

	for item := range inChan {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			_, err := writer.Write(item)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func init() {
	rootCmd.AddCommand(bucketize)

	bucketize.Flags().String("in", "", "")
	bucketize.Flags().String("out", "", "")
	bucketize.Flags().String("key", "zone", "")
	bucketize.Flags().StringSlice("dedup-key", []string{}, "")
	bucketize.Flags().Int("buckets", 100, "")
	bucketize.Flags().Int64("maxMem", 0, "Sets the max memory usage in GB. This is not a hard limit. If set to 0, no limits will be set.")
	bucketize.Flags().Uint64("cacheSize", 100_000_000, "Sets the max number of entries in the deduplication cache.")
}
