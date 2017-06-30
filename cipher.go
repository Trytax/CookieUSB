package main

import (
	"./crypto/aes"
	"./crypto/rsa"
)

const (
	EncryptionNormal  = 0xA9
	EncryptionHard    = 0xBA
	EncryptionExtreme = 0x90
	CompressionNone   = 0xF2
	CompressionZIP    = 0x88
	CompressionLZMA   = 0xC7
)

func DecryptFile(file File, rsaKeys rsa.RSAKeys) {
	decrypted, _ := rsaKeys.Decrypt(file.Key)
	file.Key = decrypted
}

func DecryptConfig(config Config, aesKeys aes.AESKey) {
	decryptedPrKey, _ := aesKeys.Decrypt(config.PrivateKey)
	decryptedPbKey, _ := aesKeys.Decrypt(config.PublicKey)
	config.PublicKey = decryptedPbKey
	config.PrivateKey = decryptedPrKey
}

func EncryptUSB(path string, rsaKeys rsa.RSAKeys, encryptionMethod byte, compressionMethod byte, rawPassword string) {

}
