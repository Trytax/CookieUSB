package main

// File : Struct for encrypted file
type File struct {
	Header            string
	NameLength        int16
	Name              string
	EncryptionMethod  byte
	KeyLength         byte
	Key               []byte
	IVLength          byte
	IV                []byte
	CompressionMethod byte
	Data              []byte
}
