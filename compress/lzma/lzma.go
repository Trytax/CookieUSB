package lzma

import (
	"bytes"
	"io"

	"github.com/lxq/lzma"
)

func Compress(data []byte) ([]byte, error) {
	var buf bytes.Buffer
	w := lzma.NewWriter(&buf)
	_, err := w.Write(data)
	w.Close()
	return buf.Bytes(), err
}

func Uncompress(data []byte) ([]byte, error) {
	buffer := bytes.NewBuffer(data)
	w := lzma.NewReader(buffer)
	var uncompressed bytes.Buffer
	_, err := io.Copy(&uncompressed, w)
	return uncompressed.Bytes(), err
}
