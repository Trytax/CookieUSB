package main

import (
	"os"

	"errors"

	"bytes"
	"encoding/binary"

	"./crypto/xor"
)

// XorKeyBA : the XorKey in byte array
var XorKeyBA = []byte{0xCB, 0x80, 0xF8, 0x51, 0x3E, 0x05, 0x02, 0xC1, 0xEE, 0x42}

func ReadBytes(f *os.File, length int, destination interface{}) error {
	buffer := make([]byte, length)
	f.Read(buffer)
	return binary.Read(bytes.NewReader(buffer), binary.LittleEndian, destination)
}

// DeserializeAsFile : deserialize a file as the File structure
func DeserializeAsFile(fileName string) (File, error) {
	f, _ := os.Open(fileName)
	defer f.Close()
	var file File

	stat, _ := f.Stat()
	length := stat.Size()

	if length < 81 {
		return file, errors.New("Invalid file")
	}

	buffer := make([]byte, 9)
	f.Read(buffer)

	key := xor.XorKey{Key: XorKeyBA}
	if string(key.Decrypt(buffer)) != "CookieUSB" {
		return file, errors.New("Invalid file")
	}
	file.Header = "CookieUSB"

	buffer = make([]byte, 2)
	f.Read(buffer)
	binary.Read(bytes.NewReader(buffer), binary.LittleEndian, &file.NameLength)

	buffer = make([]byte, file.NameLength)
	f.Read(buffer)
	binary.Read(bytes.NewReader(buffer), binary.LittleEndian, &file.Name)
	key = xor.XorKey{Key: ReverseByteArray(XorKeyBA)}
	file.Name = string(key.Decrypt([]byte(file.Name)))

	buffer = make([]byte, 1)
	f.Read(buffer)
	binary.Read(bytes.NewReader(buffer), binary.LittleEndian, &file.EncryptionMethod)

	buffer = make([]byte, 1)
	f.Read(buffer)
	binary.Read(bytes.NewReader(buffer), binary.LittleEndian, &file.KeyLength)

	buffer = make([]byte, file.KeyLength)
	f.Read(buffer)
	binary.Read(bytes.NewReader(buffer), binary.LittleEndian, &file.Key)
	// Decrypt the key with RSA private key

	buffer = make([]byte, 1)
	f.Read(buffer)
	binary.Read(bytes.NewReader(buffer), binary.LittleEndian, &file.IVLength)

	buffer = make([]byte, file.IVLength)
	f.Read(buffer)
	binary.Read(bytes.NewReader(buffer), binary.LittleEndian, &file.IV)

	buffer = make([]byte, 1)
	f.Read(buffer)
	binary.Read(bytes.NewReader(buffer), binary.LittleEndian, &file.CompressionMethod)

	currentPos, _ := f.Seek(0, 1)
	buffer = make([]byte, length-currentPos)
	f.Read(buffer)
	binary.Read(bytes.NewReader(buffer), binary.LittleEndian, &file.Data)

	return file, nil
}

// SerializeFile : serialize the File structure as a byte array
func SerializeFile(file File) ([]byte, error) {
	var data bytes.Buffer
	err := binary.Write(&data, binary.LittleEndian, file)
	return data.Bytes(), err
}

// DeserializeConfig : deserialize a file as the Config structure
func DeserializeConfig(fileName string) (Config, error) {
	f, _ := os.Open(fileName)
	defer f.Close()

	var config Config
	stat, _ := f.Stat()
	length := stat.Size()
	if length < 107 {
		return config, errors.New("Invalid file")
	}
	buffer := make([]byte, 9)
	f.Read(buffer)

	key := xor.XorKey{Key: XorKeyBA}
	if string(key.Decrypt(buffer)) != "CookieUSB" {
		return config, errors.New("Invalid file")
	}
	config.Header = "CookieUSB"

	buffer = make([]byte, 2)
	f.Read(buffer)
	binary.Read(bytes.NewReader(buffer), binary.LittleEndian, &config.PasswordLength)

	buffer = make([]byte, config.PasswordLength)
	f.Read(buffer)
	binary.Read(bytes.NewReader(buffer), binary.LittleEndian, &config.Password)
	key = xor.XorKey{Key: ReverseByteArray(XorKeyBA)}
	config.Password = string(key.Decrypt([]byte(config.Password)))

	buffer = make([]byte, 1)
	f.Read(buffer)
	binary.Read(bytes.NewReader(buffer), binary.LittleEndian, &config.IVLength)

	buffer = make([]byte, config.IVLength)
	f.Read(buffer)
	binary.Read(bytes.NewReader(buffer), binary.LittleEndian, &config.IV)

	buffer = make([]byte, 2)
	f.Read(buffer)
	binary.Read(bytes.NewReader(buffer), binary.LittleEndian, &config.KeyBits)

	buffer = make([]byte, 2)
	f.Read(buffer)
	binary.Read(bytes.NewReader(buffer), binary.LittleEndian, &config.PublicKeyLength)

	buffer = make([]byte, config.PublicKeyLength)
	f.Read(buffer)
	binary.Read(bytes.NewReader(buffer), binary.LittleEndian, &config.PublicKey)
	// Decrypt the PublicKey with AES { Key : sha256(rawPassword), IV : config.IV }

	buffer = make([]byte, 2)
	f.Read(buffer)
	binary.Read(bytes.NewReader(buffer), binary.LittleEndian, &config.PrivateKeyLength)

	buffer = make([]byte, config.PublicKeyLength)
	f.Read(buffer)
	binary.Read(bytes.NewReader(buffer), binary.LittleEndian, &config.PrivateKey)
	// Decrypt the PrivateKey with AES { Key : sha256(rawPassword), IV : config.IV }

	buffer = make([]byte, 1)
	f.Read(buffer)
	binary.Read(bytes.NewReader(buffer), binary.LittleEndian, &config.IsEncrypted)

	return config, nil
}

// SerializeConfig : serialize the Config structure as a byte array
func SerializeConfig(config Config) ([]byte, error) {
	var data bytes.Buffer
	err := binary.Write(&data, binary.LittleEndian, config)
	return data.Bytes(), err
}
