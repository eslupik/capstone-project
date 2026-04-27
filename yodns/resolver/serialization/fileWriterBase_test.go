package serialization

import (
	"io"
	"testing"
)

func TestFileWriterBase_CanGetWriter_InParallel(t *testing.T) {
	InnerWriterFactory = func(filePath string, zipAlgorithm ZipAlgorithm, compression CompressionLevel) (io.Writer, func() error, error) {
		_, w := io.Pipe()
		return w, func() error { return nil }, nil
	}
	j := NewFileWriterBase("outDir", "filePrefix", "fileExtension", 100, 2, false, ZipNone, CompressionFast)

	w1, err := j.GetWriter()
	if err != nil {
		t.Error(err)
		t.FailNow()
	}

	w2, err := j.GetWriter()
	if err != nil {
		t.Error(err)
		t.FailNow()
	}
	w2.Close()

	// This call must not block because w2 has been returned - even though w1 is still busy
	w3, err := j.GetWriter()
	if err != nil {
		t.Error(err)
		t.FailNow()
	}
	w3.Close()

	w1.Close()
}
