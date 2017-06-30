package rsa

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"errors"
)

type RSAKeys struct {
	Bits       int
	PrivateKey *rsa.PrivateKey
	PublicKey  *rsa.PublicKey
}

func (this *RSAKeys) GenerateRSAKey() error {
	priv, err := rsa.GenerateKey(rand.Reader, this.Bits)
	if err != nil {
		return err
	}
	this.PrivateKey = priv
	this.PublicKey = &priv.PublicKey
	return nil
}

func (this *RSAKeys) Encrypt(content []byte) ([]byte, error) {
	if this.PublicKey == nil || this.PrivateKey == nil {
		return nil, errors.New("There are no keys")
	}
	cipherText, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, this.PublicKey, content, []byte(""))
	if err != nil {
		return nil, err
	}
	return cipherText, nil
}

func (this *RSAKeys) Decrypt(content []byte) ([]byte, error) {
	if this.PublicKey == nil || this.PrivateKey == nil {
		return nil, errors.New("There are no keys")
	}
	text, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, this.PrivateKey, content, []byte(""))
	if err != nil {
		return nil, err
	}
	return text, nil
}
