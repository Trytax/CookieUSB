package aes

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"errors"
)

// AESKey : structure with key and IV
type AESKey struct {
	Key []byte
	IV  []byte
}

// GetKey : get the aes key
func (this *AESKey) GetKey() ([]byte, error) {
	length := len(this.Key)
	if length < 16 {
		return nil, errors.New("Minimum key length: 16")
	}
	if length >= 32 {
		return this.Key[:32], nil
	}
	if length >= 24 {
		return this.Key[:24], nil
	}
	return this.Key[:16], nil
}

// Encrypt : encrypt the content
func (this *AESKey) Encrypt(content []byte) ([]byte, error) {
	key, err := this.GetKey()
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	iv := this.IV[:aes.BlockSize]
	cipherContent := this.PKCS7Padding(content, block.BlockSize())
	mod := cipher.NewCBCEncrypter(block, iv)

	result := make([]byte, len(cipherContent))
	mod.CryptBlocks(result, cipherContent)
	return result, nil
}

// Decrypt : decrypt the content
func (this *AESKey) Decrypt(content []byte) ([]byte, error) {
	key, err := this.GetKey()
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	iv := this.IV[:aes.BlockSize]
	mod := cipher.NewCBCDecrypter(block, iv)
	cipherContent := make([]byte, len(content))
	mod.CryptBlocks(cipherContent, content)
	cipherContent = this.PKCS7UnPadding(cipherContent, block.BlockSize())
	return cipherContent, nil
}

// PKCS7Padding : pad the content and blockSize
func (this *AESKey) PKCS7Padding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}

// PKCS7UnPadding : unpad the content and blockSize
func (this *AESKey) PKCS7UnPadding(plantText []byte, blockSize int) []byte {
	length := len(plantText)
	unpadding := int(plantText[length-1])
	return plantText[:(length - unpadding)]
}
