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

// Config : Struct for configuration file
type Config struct {
	Header           string
	PasswordLength   int16
	Password         string
	IVLength         byte
	IV               []byte
	KeyBits          int16
	PublicKeyLength  int16
	PublicKey        []byte
	PrivateKeyLength int16
	PrivateKey       []byte
	IsEncrypted      bool
}
