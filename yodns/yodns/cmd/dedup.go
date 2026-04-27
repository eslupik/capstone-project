package cmd

import (
	"bufio"
	"encoding/json"
	"fmt"
	"github.com/DNS-MSMT-INET/yodns/resolver/serialization"
	"github.com/spf13/cobra"
	"golang.org/x/exp/slices"
	"io"
	"strings"
)

var dedup = &cobra.Command{
	Use:   "dedup",
	Short: "Deduplicates a sorted file full of result lines.",
	Run: func(cmd *cobra.Command, args []string) {
		inPath := Must(cmd.Flags().GetString("in"))
		outPath := Must(cmd.Flags().GetString("out"))
		keys := Must(cmd.Flags().GetStringSlice("key"))

		writer, closeFunc, err := getZipFileWriter(outPath, serialization.ZipZSTD, serialization.CompressionFast)
		if err != nil {
			panic(err)
		}
		defer closeFunc()

		r, closeFunc, err := getFileReaderSize(inPath, 32*1024*1024)
		if err != nil {
			panic(err)
		}
		defer closeFunc()

		// Use another buffered reader instead of scanner
		// https://stackoverflow.com/questions/21124327/how-to-read-a-text-file-line-by-line-in-go-when-some-lines-are-long-enough-to-ca
		b := bufio.NewReaderSize(r, 32*1024*1024)

		var lastObj map[string]json.RawMessage
		var lastKeys []string
		var lastTags string
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

			var nextObj map[string]json.RawMessage
			err := json.Unmarshal(data, &nextObj)
			if err != nil {
				panic(err)
			}

			nextKeys := make([]string, 0, len(keys))
			for _, key := range keys {
				var nextKey any
				err = json.Unmarshal(nextObj[key], &nextKey)
				if err != nil {
					panic(err)
				}
				nextKeys = append(nextKeys, fmt.Sprintf("%v", nextKey))
			}

			var nextTags string
			if _, ok := nextObj["tags"]; ok {
				err = json.Unmarshal(nextObj["tags"], &nextTags)
				if err != nil {
					panic(err)
				}

			}

			if len(lastKeys) == 0 {
				lastObj = nextObj
				lastKeys = nextKeys
				lastTags = nextTags
				continue
			}

			if slices.Equal(nextKeys, lastKeys) {
				lastTags = mergeTags(lastTags, nextTags)

				// If it is a rescan, chose the rescan
				if strings.Contains(nextTags, TagRescan) {
					lastObj = nextObj
				}

				continue
			}

			// else - write value
			b, err := json.Marshal(lastTags)
			if err != nil {
				panic(err)
			}

			if _, ok := lastObj["tags"]; ok {
				lastObj["tags"] = b
			}

			writeToLine(lastObj, writer)

			lastObj = nextObj
			lastKeys = nextKeys
			lastTags = nextTags
		}

		if len(lastKeys) != 0 {
			b, err := json.Marshal(lastTags)
			if err != nil {
				panic(err)
			}

			if _, ok := lastObj["tags"]; ok {
				lastObj["tags"] = b
			}
			writeToLine(lastObj, writer)
		}
	},
}

func writeToLine(obj map[string]json.RawMessage, writer io.Writer) {
	bytes, err := json.Marshal(obj)
	if err != nil {
		panic(err)
	}
	_, err = writer.Write(bytes)
	if err != nil {
		panic(err)
	}
	_, err = writer.Write([]byte("\n"))
	if err != nil {
		panic(err)
	}
}

func init() {
	rootCmd.AddCommand(dedup)

	dedup.Flags().String("in", "", "")
	dedup.Flags().String("out", "", "")
	dedup.Flags().StringSlice("key", []string{"zone"}, "")
}
