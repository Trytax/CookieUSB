package main

// File : Struct for encrypted file
type File struct {
	Header            string
	Name              string
	EncryptionMethod  byte
	Key               []byte
	IV                []byte
	CompressionMethod byte
	Data              []byte
}

// Config : Struct for configuration file
type Config struct {
	Header      string
	Password    string
	IV          []byte
	KeyBits     int16
	PublicKey   []byte
	PrivateKey  []byte
	IsEncrypted bool
}
