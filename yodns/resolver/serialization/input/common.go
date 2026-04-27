package input

import (
	"bufio"
	"github.com/klauspost/compress/zstd"
	"io"
	"os"
	"strings"
)

func getFileReader(path string, bufferSize int) (io.Reader, func() error, error) {
	outFile, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	bufReader := bufio.NewReaderSize(outFile, bufferSize)

	if !strings.HasSuffix(path, ".zst") {
		return bufReader, outFile.Close, nil
	}

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

func getStdInReader(bufferSize int) io.Reader {
	bufReader := bufio.NewReaderSize(os.Stdin, bufferSize)
	return bufReader
}
