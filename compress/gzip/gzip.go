package gzip

import (
	"bytes"
	"compress/gzip"
	"io"
)

func Compress(data []byte) ([]byte, error) {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	_, err := zw.Write(data)
	zw.Close()
	return buf.Bytes(), err
}

func Uncompress(data []byte) ([]byte, error) {
	buffer := bytes.NewBuffer(data)
	zw, err := gzip.NewReader(buffer)
	var uncompressed bytes.Buffer
	io.Copy(&uncompressed, zw)
	return uncompressed.Bytes(), err
}
