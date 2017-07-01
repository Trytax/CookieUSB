package main

import (
	"crypto/rand"
	"errors"
	"fmt"
	"os"

	"./crypto/xor"

	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"

	"github.com/fatih/color"
)

// Levels
const (
	Success = iota
	Error
	Warning
	Task
	Normal
)

// Debug : Print message with a color
func Debug(message string, level int) {
	switch level {
	case Success:
		fmt.Println(color.HiGreenString("[+]"), message)
	case Error:
		fmt.Println(color.HiRedString("[-]"), message)
	case Warning:
		fmt.Println(color.HiYellowString("[!]"), message)
	case Task:
		fmt.Println(color.HiCyanString("[~]"), message)
	case Normal:
		fmt.Println(color.HiMagentaString("[*]"), message)
	}
}

// ReverseByteArray : Reverse a byte array
func ReverseByteArray(data []byte) []byte {
	reversed := make([]byte, len(data))
	for i, j := 0, len(data)-1; i < j; i, j = i+1, j-1 {
		reversed[i], reversed[j] = data[j], data[i]
	}
	return reversed
}

func GetConfig(path string) (Config, error) {
	if _, err := os.Stat(path + "/" + configName); os.IsNotExist(err) {
		return Config{}, errors.New("The file doesn't exist")
	}
	return DeserializeConfig(path + "/" + configName)
}

func GenerateIV() ([]byte, error) {
	b := make([]byte, 16)
	_, err := rand.Read(b)
	return b, err
}

func GenerateKey() ([]byte, error) {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	return b, err
}

// Contains : Check if the string is in the array
func Contains(s string, list []string) bool {
	for _, e := range list {
		if e == s {
			return true
		}
	}
	return false
}

func GetPEMKey(key *rsa.PrivateKey) (privateKey string, publicKey string, err error) {
	prKeyBlock := pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}
	pbKey := key.PublicKey
	pbKeyDer, err := x509.MarshalPKIXPublicKey(&pbKey)
	pbKeyBlock := pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pbKeyDer,
	}
	return string(pem.EncodeToMemory(&prKeyBlock)), string(pem.EncodeToMemory(&pbKeyBlock)), err
}

func GetRSAKeys(publicKey []byte, privateKey []byte) (*rsa.PrivateKey, *rsa.PublicKey, error) {
	block, _ := pem.Decode(publicKey)
	if block == nil {
		return nil, nil, errors.New("Error")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, nil, err
	}
	var pbKey *rsa.PublicKey
	switch pub := pub.(type) {
	case *rsa.PublicKey:
		pbKey = pub
	default:
		break
	}
	block, _ = pem.Decode(privateKey)
	if block == nil {
		return nil, nil, errors.New("Error")
	}
	priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, nil, err
	}
	return priv, pbKey, nil
}

func IsBlacklisted(fileName string) bool {
	blacklist := []string{configName, "CookieUSB_win.exe", "CookieUSB_darwin", "CookieUSB_win"}
	return Contains(fileName, blacklist)
}

func IsEncrypted(data []byte) bool {
	key := xor.XorKey{Key: FileKey}
	decryptedData := key.Decrypt(data)
	_, err := DeserializeAsFile(decryptedData)
	if err != nil {
		return false
	}
	return true
}
