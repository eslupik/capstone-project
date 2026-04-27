package cmd

import (
	"bufio"
	"fmt"
	"github.com/rs/zerolog"
	"github.com/spf13/cobra"
	"github.com/DNS-MSMT-INET/yodns/resolver"
	"github.com/DNS-MSMT-INET/yodns/resolver/model"
	"github.com/DNS-MSMT-INET/yodns/resolver/serialization"
	"github.com/DNS-MSMT-INET/yodns/resolver/serialization/protobuf"
	"golang.org/x/sync/errgroup"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"
)

var ReplaceRescan = &cobra.Command{
	Use:   "replaceRescan",
	Short: "Replaces rescanned domains in the dataset",
	Long: "Sometimes domains have to be rescanned due to incidents that affect data quality, such as network outages. " +
		"Before publishing a dataset, we want to remove all potentially faulty domains from the files and store them separately. " +
		"Especially with regards to publishing a dataset this makes sense, as this is typically what is expected from a dataset. ",
	Run: func(cmd *cobra.Command, args []string) {
		in := Must(cmd.Flags().GetString("in"))
		zip := Must(cmd.Flags().GetString("zip"))
		outDir := Must(cmd.Flags().GetString("out-dir"))
		originalOutDir := Must(cmd.Flags().GetString("original-out-dir"))
		tags := Must(cmd.Flags().GetString("tags"))
		format := Must(cmd.Flags().GetString("format"))
		parallelism := Must(cmd.Flags().GetInt("parallelism"))
		rescanFiles := Must(cmd.Flags().GetString("rescan-files"))
		skip := Must(cmd.Flags().GetInt("skip"))

		logger := zerolog.New(os.Stderr).Level(zerolog.InfoLevel).With().Timestamp().Logger()

		zipAlgo, compression, err := serialization.ParseZip(zip)
		if err != nil {
			panic(err)
		}

		if err := os.MkdirAll(outDir, os.ModePerm); err != nil {
			panic(err)
		}
		if err := os.MkdirAll(originalOutDir, os.ModePerm); err != nil {
			panic(err)
		}

		// Map of all domains that have been rescanned
		rescanMap, err := loadRescannedDomains(rescanFiles, 0, true, logger)
		if err != nil {
			panic(err)
		}

		g := errgroup.Group{}
		g.SetLimit(parallelism)

		files, err := filepath.Glob(in)
		if err != nil {
			panic(err)
		}
		slices.Sort(files)
		files = files[skip:]

		logger.Info().Msgf("Skip: %v. Processing %v files. Starting with %v", skip, len(files), files[0])

		// Channel where the "original" (i.e. potentially faulty domains that had to be rescanned) are written to.
		originalChan := make(chan resolver.Result, 200)
		done := make(chan struct{})
		go func() {
			originalWriter(tags, format, zipAlgo, compression, uint32(parallelism), originalOutDir, originalChan)
			done <- struct{}{}
		}()

		start := time.Now()
		for i, file := range files {
			if i%1000 == 0 {
				logger.Info().Msgf("Processing file %v of %v. ETA: %v", i, len(files), start.Add(time.Duration(int(float64(time.Since(start))*float64(len(files))/float64(i+1)))))
			}

			f := file
			out := filepath.Join(outDir, filepath.Base(f))
			g.Go(func() error {
				processFile(f, out, format, zipAlgo, compression, rescanMap, originalChan)
				return nil
			})
		}

		if err := g.Wait(); err != nil {
			panic(err)
		}

		close(originalChan)
		<-done
	},
}

func originalWriter(tags string, format string,
	zipAlgo serialization.ZipAlgorithm,
	compression serialization.CompressionLevel,
	parallelism uint32,
	outDir string,
	originalChan <-chan resolver.Result) {
	// We want approximately one writer per reader -
	// if we are parsing a rescanned section of the data,
	// almost all data read needs to go through here.
	originalOutWriter := getParallelWriter(outDir, 200, format, zipAlgo, compression, parallelism)

	for p := range originalChan {

		modifiedDNs := make([]resolver.TaggedDomainName, 0, len(p.Domains))
		for _, dn := range p.Domains {
			if dn.Tags != "" {
				dn.Tags = strings.TrimSuffix(dn.Tags, ";") + ";" + tags
			}
			modifiedDNs = append(modifiedDNs, dn)
		}

		p.Domains = modifiedDNs

		if err := originalOutWriter.WriteAsync(p); err != nil {
			panic(err)
		}
	}

	if err := originalOutWriter.Wait(); err != nil {
		panic(err)
	}
}

func processFile(in string, out string, format string,
	zipAlgo serialization.ZipAlgorithm,
	compression serialization.CompressionLevel,
	rescanMap *sync.Map, originalChan chan<- resolver.Result) {
	outWriter, closeFunc, err := getZipFileWriter(out, zipAlgo, compression)
	if err != nil {
		panic(err)
	}
	defer closeFunc()

	c := make(chan resolver.Result, 20)
	reader := getFilteredReaderZip(in, format, false, nil, 0)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				panic(fmt.Errorf("%v %v", out, r))
			}
		}()

		if err := reader.ReadTo(c); err != nil {
			panic(fmt.Errorf("%v %w", out, err))
		}
	}()

	for p := range c {

		wasRescanned := false
		for _, dn := range p.Domains {
			if dn.Tags == "" {
				continue
			}

			if _, ok := rescanMap.Load(dn.Name); ok {
				wasRescanned = true
				break
			}
		}

		if wasRescanned {
			originalChan <- p
			continue
		}

		if err := protobuf.SerializeResult(p, outWriter, protobuf.ToMessage); err != nil {
			panic(err)
		}
	}
}

func loadRescannedDomains(rescanCsv string, idx int, hasHeader bool, logger zerolog.Logger) (*sync.Map, error) {
	files, err := filepath.Glob(rescanCsv)
	if err != nil {
		return nil, err
	}
	result := &sync.Map{}

	for i, file := range files {
		if i%100 == 0 {
			logger.Info().Msgf("Loading rescanned domains. File %v of %v", i, len(files))
		}

		reader, closeFunc, err := getFileReader(file)
		if err != nil {
			return nil, err
		}

		scanner := bufio.NewScanner(reader)

		if hasHeader {
			scanner.Scan()
		}

		for scanner.Scan() {
			if scanner.Err() != nil {
				panic(scanner.Err())
			}

			parts := strings.Split(scanner.Text(), ",")
			domain := model.MustNewDomainName(parts[idx])
			result.Store(domain, nil)
		}

		if err := closeFunc(); err != nil {
			return nil, err
		}
	}

	return result, nil
}

func init() {
	rootCmd.AddCommand(ReplaceRescan)

	ReplaceRescan.Flags().String("in", "", "Input file")
	ReplaceRescan.Flags().String("rescan-files", "", "Glob pattern to csv files that contain the rescanned domains.")

	ReplaceRescan.Flags().String("out-dir", "", "Output directory of the filtered data")
	ReplaceRescan.Flags().String("original-out-dir", "", "Output of the extracted original domains.")

	ReplaceRescan.Flags().String("format", "protobuf", "File format. Protobuf or json.")
	ReplaceRescan.Flags().String("zip", "zstd:fast", "Whether to zip the output.")
	ReplaceRescan.Flags().Int("parallelism", 100, "Number of files to mergeSingleFile in parallel.")
	ReplaceRescan.Flags().Int("skip", 0, "Number of files to skip.")
	ReplaceRescan.Flags().String("tags", "", "Tags to add to the original files.")
}
