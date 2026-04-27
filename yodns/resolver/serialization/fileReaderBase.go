package serialization

import (
	"bufio"
	"fmt"
	"github.com/klauspost/compress/gzip"
	"github.com/klauspost/compress/zstd"
	"github.com/DNS-MSMT-INET/yodns/resolver"
	"io"
	"os"
	"path"
	"strings"
)

type Read struct {
	Result resolver.Result
	Error  error
}

func OpenReader(fileName string, zipAlgorithm ZipAlgorithm) (io.Reader, func() error, error) {
	reader, err := os.Open(fileName)
	if err != nil {
		return nil, nil, err
	}

	// Increase buffer capacity because lines can be pretty long
	bufReader := bufio.NewReaderSize(reader, 32*1024*1024)

	switch zipAlgorithm {
	case ZipNone:
		return bufReader, func() error { return nil }, nil
	case ZipDeflate:
		return nil, nil, fmt.Errorf("deflate algorithm is not supported yet")
	case ZipGZIP:
		zr, err := gzip.NewReader(bufReader)
		return zr, zr.Close, err
	case ZipZSTD, ZipDefault:
		zr, err := zstd.NewReader(bufReader)
		return zr, func() error { zr.Close(); return nil }, err
	default:
		return nil, nil, fmt.Errorf("unknown zip algorithm: %v", zipAlgorithm)
	}
}

func GetZipAlgoFromExtensions(fileName string) ZipAlgorithm {
	extension := strings.ToLower(path.Ext(fileName))
	switch extension {
	case ".zip":
		return ZipDeflate
	case ".gz", ".gzip":
		return ZipGZIP
	case ".zst", ".zstd":
		return ZipZSTD
	default:
		return ZipNone
	}
}
