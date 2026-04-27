package serialization

import (
	"bufio"
	"errors"
	"fmt"
	"github.com/google/uuid"
	"github.com/klauspost/compress/gzip"
	"github.com/klauspost/compress/zip"
	"github.com/klauspost/compress/zstd"
	"github.com/DNS-MSMT-INET/yodns/resolver/common"
	"io"
	"os"
	"path"
	"strings"
	"sync/atomic"
)

var ErrPoolClosed = errors.New("pool closed")

// ZipAlgorithm is the type of the zip algorithm to use.
type ZipAlgorithm int

// CompressionLevel controls the level of compression to use.
type CompressionLevel int

const (
	// ZipNone will not compress the output
	ZipNone ZipAlgorithm = iota

	// ZipDefault will choose the default compression algorithm.
	// which is currently ZipZSTD.
	ZipDefault

	// ZipDeflate will use the Deflate compression algorithm.
	// It will produce a .zip archive.
	// When using Deflate, consider adding some writeParallelism,
	// as it does not parallelize inherently. However, too much
	// writeParallelism comes with other downsides.
	ZipDeflate

	// ZipZSTD will use the ZSTD compression algorithm.
	// It will produce a .zst file
	// It provides the fastest and best compression.
	ZipZSTD

	// ZipGZIP will use the GZIP compression algorithm.
	// It will produce a .gz file
	// When using GZIP, consider adding some writeParallelism,
	// as it does not parallelize inherently. However, too much
	// writeParallelism comes with other downsides.
	ZipGZIP
)

const (
	// CompressionFastest provides the fastest compression speed with the given ZipAlgorithm
	// When changing compression levels, always make sure that your machine can
	// write the data as fast as it is collected. Otherwise memory will overflow.
	CompressionFastest CompressionLevel = iota

	// CompressionFast provides a fast compression speed with the given ZipAlgorithm
	// But smaller file sizes than CompressionFastest.
	// When changing compression levels, always make sure that your machine can
	// write the data as fast as it is collected. Otherwise memory will overflow.
	CompressionFast

	// CompressionBetter provides a smaller file size than CompressionFast and CompressionFastest
	// using the given ZipAlgorithm. CompressionBetter can lead to memory on many machines,
	// as data cannot be written as fast as it is collected. When changing compression levels,
	// always make sure that data can be written fast enough
	CompressionBetter

	// CompressionBest provides a smaller file size than CompressionFast and CompressionFastest
	// using the given ZipAlgorithm.
	CompressionBest
)

var _ io.WriteCloser = new(pooledWriter)

// InnerWriterFactory lets you override writer creation for testing purposes
var InnerWriterFactory = newBufferedFileWriter

type pooledWriter struct {
	itemsWritten   uint
	fileSize       uint
	pool           chan *pooledWriter
	inner          io.Writer
	innerCloseFunc func() error
	innerClosed    bool
}

// Close returns the writer to the pool. If the
// maximum allowed number of items has been written,
// the underlying writer is closed.
func (w *pooledWriter) Close() error {
	defer w.returnToPool()

	w.itemsWritten++
	if w.itemsWritten == w.fileSize {
		w.innerClosed = true
		err := w.innerCloseFunc()
		return err
	}

	return nil
}

func (w *pooledWriter) returnToPool() {
	w.pool <- w
}

func (w *pooledWriter) Write(p []byte) (n int, err error) {
	return w.inner.Write(p)
}

type FileWriterBase struct {
	OutDir           string
	FilePrefix       string
	FileExtension    string
	OutputFileSize   uint
	ZipAlgorithm     ZipAlgorithm
	CompressionLevel CompressionLevel

	// RandomFileSuffix avoids that subsequent runs in the same directory overwrite files
	// Just a small safeguard against data loss.
	RandomFileSuffix string

	fileIdx     uint32
	renameFiles bool
	writerPool  chan *pooledWriter
	writersIdx  uint32
}

func NewFileWriterBase(outDir string,
	filePrefix string,
	fileExtension string,
	outputFileSize uint,
	parallelFiles uint32,
	renameFiles bool,
	zipAlgo ZipAlgorithm,
	compression CompressionLevel) *FileWriterBase {

	// Init parallelFiles writers and put them into the pool.
	randomSuffix := uuid.New().String()[:8]
	writerPool := make(chan *pooledWriter, parallelFiles)
	for i := uint32(0); i < parallelFiles; i++ {
		filePath := getFilePath(outDir, i, filePrefix, fileExtension, randomSuffix, zipAlgo)
		tempFilePath := ""
		if renameFiles {
			tempFilePath = getFilePath(outDir, i, filePrefix, "tmp", randomSuffix, ZipNone)
		}
		writer, err := newPooledFileWriter(filePath, tempFilePath, outputFileSize, writerPool, zipAlgo, compression)
		if err != nil {
			panic(err)
		}
		writerPool <- writer
	}

	return &FileWriterBase{
		OutDir:           outDir,
		FilePrefix:       filePrefix,
		OutputFileSize:   outputFileSize,
		FileExtension:    fileExtension,
		ZipAlgorithm:     zipAlgo,
		CompressionLevel: compression,
		RandomFileSuffix: randomSuffix,
		fileIdx:          parallelFiles,
		writerPool:       writerPool,
		renameFiles:      renameFiles,
	}
}

func (j *FileWriterBase) GetWriter() (io.WriteCloser, error) {
	// wait for a writer to be available
	writerToUse, ok := <-j.writerPool
	if !ok {
		return nil, ErrPoolClosed
	}

	// if the writer can still write, return it
	if !writerToUse.innerClosed {
		return writerToUse, nil
	}

	// else, create a new writer
	// will be added to the pool again when Close() is called
	fileIdx := atomic.AddUint32(&j.fileIdx, 1) - 1
	filePath := getFilePath(j.OutDir, fileIdx, j.FilePrefix, j.FileExtension, j.RandomFileSuffix, j.ZipAlgorithm)
	tempFilePath := ""
	if j.renameFiles {
		tempFilePath = getFilePath(j.OutDir, fileIdx, j.FilePrefix, "tmp", j.RandomFileSuffix, ZipNone)
	}

	return newPooledFileWriter(filePath, tempFilePath, j.OutputFileSize, j.writerPool, j.ZipAlgorithm, j.CompressionLevel)
}

// CloseAll flushes and closes all writer in the pool
// Not safe to use concurrently with GetWriter() or writing
func (j *FileWriterBase) CloseAll() error {
	close(j.writerPool)
	var err error
	for i := 0; i < cap(j.writerPool); i++ {
		writer := <-j.writerPool
		err = common.ChainErr(err, writer.innerCloseFunc())
	}
	return err
}

func newPooledFileWriter(filePath string,
	tempFilePath string,
	outFileSize uint,
	writerPool chan *pooledWriter,
	zipAlgorithm ZipAlgorithm,
	compression CompressionLevel) (*pooledWriter, error) {

	pathToUse := filePath
	if tempFilePath != "" {
		pathToUse = tempFilePath
	}
	w, closeFunc, err := InnerWriterFactory(pathToUse, zipAlgorithm, compression)

	closeFuncToUse := closeFunc
	if tempFilePath != "" {
		closeFuncToUse = func() error {
			err := common.ChainErr(closeFunc(), nil)
			return common.ChainErr(os.Rename(tempFilePath, filePath), err)
		}
	}

	if err != nil {
		return nil, err
	}
	return &pooledWriter{
		itemsWritten:   0,
		fileSize:       outFileSize,
		pool:           writerPool,
		inner:          w,
		innerClosed:    false,
		innerCloseFunc: closeFuncToUse,
	}, nil
}

func newBufferedFileWriter(filePath string,
	zipAlgorithm ZipAlgorithm,
	compression CompressionLevel) (io.Writer, func() error, error) {
	outFile, err := os.Create(filePath)
	if err != nil {
		return nil, nil, err
	}
	writer := bufio.NewWriter(outFile)

	if zipAlgorithm == ZipNone {
		return writer, func() error {
			err := common.ChainErr(writer.Flush(), nil)
			return common.ChainErr(outFile.Close(), err)
		}, nil
	}

	zw, closeFunc, err := InitZipWriter(writer, zipAlgorithm, compression)
	return zw, func() error {
		err := common.ChainErr(closeFunc(), nil)
		err = common.ChainErr(writer.Flush(), err)
		return common.ChainErr(outFile.Close(), err)
	}, err
}

func getFilePath(basePath string, fileIdx uint32, filePrefix string, outFileExtension string, randomSuffix string, zipAlgorithm ZipAlgorithm) string {
	fileName := fmt.Sprintf("%v_%08d_%v.%v", filePrefix, fileIdx, randomSuffix, outFileExtension)
	filePath := path.Join(basePath, fileName)
	switch zipAlgorithm {
	case ZipNone:
		return filePath
	case ZipDeflate:
		return fmt.Sprintf("%v.zip", filePath)
	case ZipGZIP:
		return fmt.Sprintf("%v.gz", filePath)
	case ZipZSTD, ZipDefault:
		return fmt.Sprintf("%v.zst", filePath)
	default:
		panic(fmt.Errorf("unknown zip algorithm: %v", zipAlgorithm))
	}
}

func InitZipWriter(writer io.Writer, zipAlgorithm ZipAlgorithm, compression CompressionLevel) (io.Writer, func() error, error) {
	switch zipAlgorithm {
	case ZipNone:
		return writer, func() error { return nil }, nil
	case ZipDeflate:
		zw := zip.NewWriter(writer)
		archive, err := zw.Create("data")
		return archive, zw.Close, err
	case ZipGZIP:
		zw, err := gzip.NewWriterLevel(writer, toGZIPCompression(compression))
		return zw, zw.Close, err
	case ZipZSTD, ZipDefault:
		zw, err := zstd.NewWriter(writer, zstd.WithEncoderLevel(toZSTDEncoderLevel(compression)))
		return zw, zw.Close, err
	default:
		return nil, nil, fmt.Errorf("unknown zip algorithm: %v", zipAlgorithm)
	}
}

func toZSTDEncoderLevel(compression CompressionLevel) zstd.EncoderLevel {
	switch compression {
	case CompressionFastest:
		return zstd.SpeedFastest
	case CompressionFast:
		return zstd.SpeedDefault
	case CompressionBetter:
		return zstd.SpeedBetterCompression
	case CompressionBest:
		return zstd.SpeedBestCompression
	default:
		panic(fmt.Sprintf("Unkown comperession level %v", compression))
	}
}

func toGZIPCompression(compression CompressionLevel) int {
	switch compression {
	case CompressionFastest:
		return gzip.BestSpeed
	case CompressionFast:
		return gzip.DefaultCompression // 5
	case CompressionBetter:
		return 7
	case CompressionBest:
		return gzip.BestCompression
	default:
		panic(fmt.Sprintf("Unkown comperession level %v", compression))
	}
}

// ParseZip parses a string with format 'algo' or 'algo:level' e.g. 'zstd' or 'zstd:fastest'
// Allowed algorithms: "" (none), "gzip", "default" (zstd), "zstd", "deflate"
// Allowed compression levels: "default" (fastest), "fastest", "fast", "better", "best".
// Note that for 'deflate', the compression level will not make any difference.
func ParseZip(zipSetting string) (ZipAlgorithm, CompressionLevel, error) {
	parts := strings.Split(zipSetting, ":")
	if len(parts) > 2 {
		return 0, 0, fmt.Errorf("zip format string '%v' cannot be parsed", zipSetting)
	}

	zipAlgo := ZipNone
	compression := CompressionFastest

	switch strings.TrimSpace(strings.ToLower(parts[0])) {
	case "", "none":
		zipAlgo = ZipNone
	case "gzip":
		zipAlgo = ZipGZIP
	case "default", "zst", "zstd":
		zipAlgo = ZipZSTD
	case "deflate":
		zipAlgo = ZipDeflate
	default:
		return 0, 0, fmt.Errorf("zip algorithm '%v' is not known", zipSetting)
	}

	if len(parts) == 1 {
		return zipAlgo, compression, nil
	}

	switch strings.TrimSpace(strings.ToLower(parts[1])) {
	case "", "fastest", "default":
		compression = CompressionFastest
	case "fast":
		compression = CompressionFast
	case "better":
		compression = CompressionBetter
	case "best":
		compression = CompressionBest
	default:
		return 0, 0, fmt.Errorf("compression level '%v' is not known", zipSetting)
	}

	return zipAlgo, compression, nil
}
