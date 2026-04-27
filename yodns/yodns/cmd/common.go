package cmd

import (
	"bufio"
	encodingjson "encoding/json"
	"fmt"
	"github.com/jellydator/ttlcache/v3"
	"github.com/klauspost/compress/gzip"
	"github.com/klauspost/compress/zstd"
	"github.com/DNS-MSMT-INET/yodns/resolver"
	"github.com/DNS-MSMT-INET/yodns/resolver/common"
	"github.com/DNS-MSMT-INET/yodns/resolver/serialization"
	"github.com/DNS-MSMT-INET/yodns/resolver/serialization/json"
	"github.com/DNS-MSMT-INET/yodns/resolver/serialization/protobuf"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

func Must[T any](obj T, err error) T {
	if err != nil {
		panic(err)
	}
	return obj
}

type SyncMapCapacity[K comparable, V any] struct {
	inner   *ttlcache.Cache[K, V]
	innerMu sync.Mutex
}

func NewSyncMapCapacity[K comparable, V any](capacity uint64) *SyncMapCapacity[K, V] {
	return &SyncMapCapacity[K, V]{
		inner:   ttlcache.New(ttlcache.WithCapacity[K, V](capacity)),
		innerMu: sync.Mutex{},
	}
}

func (s *SyncMapCapacity[K, V]) LoadOrStore(k K, v V) (V, bool) {
	s.innerMu.Lock()
	defer s.innerMu.Unlock()

	if existing := s.inner.Get(k); existing != nil {
		return existing.Value(), true
	}
	s.inner.Set(k, v, time.Hour)
	return v, false
}

var _ reader = new(FilteredReader)

type FilteredReader struct {
	Inner      reader
	Predicates []FilterPredicate[resolver.Result]
}

func (f FilteredReader) ReadTo(outChan chan<- resolver.Result) error {
	bufChan := make(chan resolver.Result)

	go func() {
	outer:
		for result := range bufChan {
			for _, predicate := range f.Predicates {
				if !predicate(result) {
					continue outer
				}
			}

			x := result
			outChan <- x
		}

		close(outChan)
	}()

	return f.Inner.ReadTo(bufChan)
}

func inferFormat(inPattern string) (string, error) {
	if strings.HasSuffix(inPattern, ".json.zst") || strings.HasSuffix(inPattern, ".json") {
		return "json", nil
	}
	if strings.HasSuffix(inPattern, ".pb.zst") || strings.HasSuffix(inPattern, ".pb") {
		return "protobuf", nil
	}
	if strings.Contains(inPattern, "*") {
		m, err := filepath.Glob(inPattern)
		if err != nil {
			return "", fmt.Errorf("unable to access %v: %w", inPattern, err)
		}
		if len(m) > 0 {
			return inferFormat(m[0])
		}
	}
	// Default format
	return "protobuf", nil
}

func getFilteredReaderZip(inPattern string,
	format string,
	parallel bool,
	zip *serialization.ZipAlgorithm,
	timeout time.Duration,
	predicates ...FilterPredicate[resolver.Result]) reader {
	var inner reader
	if strings.ToLower(format) == "protobuf" {
		r, err := protobuf.NewFileReaderTimeout(inPattern, timeout)
		if err != nil {
			panic(err)
		}

		r.Zip = zip
		inner = r
	} else if strings.ToLower(format) == "json" {
		r := json.NewReader(inPattern, parallel)
		r.Zip = zip
		inner = r
	} else {
		panic(fmt.Errorf("unkown format: %v", format))
	}

	return FilteredReader{
		Inner:      inner,
		Predicates: predicates,
	}
}

func getFileReader(path string) (io.Reader, func() error, error) {
	outFile, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	bufReader := bufio.NewReader(outFile)
	if strings.HasSuffix(path, ".zst") {
		zr, err := zstd.NewReader(bufReader)
		if err != nil {
			outFile.Close()
			return nil, nil, err
		}

		return zr, func() error {
			zr.Close()
			return outFile.Close()
		}, nil
	}

	if strings.HasSuffix(path, ".gz") {
		zr, err := gzip.NewReader(bufReader)
		if err != nil {
			outFile.Close()
			return nil, nil, err
		}

		return zr, func() error {
			zr.Close()
			return outFile.Close()
		}, nil
	}

	return bufReader, outFile.Close, nil
}

func getFileReaderSize(path string, bufferSize int) (io.Reader, func() error, error) {
	outFile, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	bufReader := bufio.NewReaderSize(outFile, bufferSize)

	if strings.HasSuffix(path, ".zst") {
		zr, err := zstd.NewReader(bufReader)
		if err != nil {
			outFile.Close()
			return nil, nil, err
		}

		return zr, func() error {
			zr.Close()
			return outFile.Close()
		}, nil
	}

	if strings.HasSuffix(path, ".gz") {
		zr, err := gzip.NewReader(bufReader)
		if err != nil {
			outFile.Close()
			return nil, nil, err
		}

		return zr, func() error {
			zr.Close()
			return outFile.Close()
		}, nil
	}

	return bufReader, outFile.Close, nil
}

func getZipFileWriter(path string, zip serialization.ZipAlgorithm, compression serialization.CompressionLevel) (io.Writer, func() error, error) {
	outFile, err := os.Create(path)
	if err != nil {
		return nil, nil, err
	}
	w := bufio.NewWriter(outFile)
	zw, closeFn, err := serialization.InitZipWriter(w, zip, compression)
	return zw, func() error {
		closeFn()
		w.Flush()
		return outFile.Close()
	}, err
}

func getWriter(outPath string, filesize uint, format string, zip bool) writer {
	if zip {
		return getParallelWriter(outPath, filesize, format, serialization.ZipZSTD, serialization.CompressionFast, 1)
	}
	return getParallelWriter(outPath, filesize, format, serialization.ZipNone, serialization.CompressionFast, 1)
}

func getParallelWriter(outPath string, filesize uint, format string, zipAlgo serialization.ZipAlgorithm, compression serialization.CompressionLevel, parallelism uint32) writer {
	if strings.ToLower(format) == "protobuf" {
		return protobuf.NewWriter(outPath, "output", filesize, zipAlgo, compression, parallelism)
	}
	if strings.ToLower(format) == "json" {
		return json.NewWriter(outPath, "output", filesize, zipAlgo, compression, parallelism)
	}

	panic(fmt.Errorf("unkown format: %v", format))
}

func writeResult[T any](w io.Writer, result T) {
	bytes, err := encodingjson.Marshal(result)
	if err != nil {
		panic(err)
	}
	if _, err = w.Write(bytes); err != nil {
		panic(err)
	}
	if _, err = w.Write([]byte("\n")); err != nil {
		panic(err)
	}
}

func mergeTags(tags1 string, tags2 string) string {
	r := make(map[string]any)

	for _, tag := range strings.Split(tags1, ";") {
		r[tag] = nil
	}
	for _, tag := range strings.Split(tags2, ";") {
		r[tag] = nil
	}

	return strings.Join(common.Keys(r), ";")
}
