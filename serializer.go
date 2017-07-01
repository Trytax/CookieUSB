package main

import (
	"bytes"
	"encoding/gob"
	"errors"
	"io/ioutil"

	"./crypto/xor"
)

// XorKeyBA : the XorKey in byte array
var XorKeyBA = []byte{0xCB, 0x80, 0xF8, 0x51, 0x3E, 0x05, 0x02, 0xC1, 0xEE, 0x42}

// DeserializeAsFile : deserialize a file as the File structure
func DeserializeAsFile(data []byte) (File, error) {
	var file File
	buffer := bytes.NewBuffer(data)
	dec := gob.NewDecoder(buffer)
	err := dec.Decode(&file)
	if len(data) < 81 {
		return file, errors.New("Invalid file")
	}
	key := xor.XorKey{Key: XorKeyBA}
	file.Header = string(key.Decrypt([]byte(file.Header)))
	if file.Header != "CookieUSB" {
		return file, errors.New("Invalid file")
	}
	key = xor.XorKey{Key: ReverseByteArray(XorKeyBA)}
	file.Name = string(key.Decrypt([]byte(file.Name)))
	// Decrypt the key with RSA private key
	return file, err
}

// SerializeFile : serialize the File structure as a byte array
func SerializeFile(file File) ([]byte, error) {
	var buffer bytes.Buffer
	enc := gob.NewEncoder(&buffer)
	err := enc.Encode(file)
	return buffer.Bytes(), err
}

// DeserializeConfig : deserialize a file as the Config structure
func DeserializeConfig(fileName string) (Config, error) {
	b, _ := ioutil.ReadFile(fileName)
	var config Config
	buffer := bytes.NewBuffer(b)
	dec := gob.NewDecoder(buffer)
	err := dec.Decode(&config)
	if len(b) < 107 {
		return config, errors.New("Invalid file")
	}
	key := xor.XorKey{Key: XorKeyBA}
	config.Header = string(key.Decrypt([]byte(config.Header)))
	if config.Header != "CookieUSB" {
		return config, errors.New("Invalid file")
	}
	key = xor.XorKey{Key: ReverseByteArray(XorKeyBA)}
	config.Password = string(key.Decrypt([]byte(config.Password)))
	// Decrypt the PublicKey with AES { Key : sha256(rawPassword), IV : config.IV }
	// Decrypt the PrivateKey with AES { Key : sha256(rawPassword), IV : config.IV }
	return config, err
}

// SerializeConfig : serialize the Config structure as a byte array
func SerializeConfig(config Config) ([]byte, error) {
	var buffer bytes.Buffer
	enc := gob.NewEncoder(&buffer)
	err := enc.Encode(config)
	return buffer.Bytes(), err
}
