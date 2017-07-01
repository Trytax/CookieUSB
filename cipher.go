package main

import (
	"crypto/sha256"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"

	"./compress/gzip"
	"./compress/lzma"
	"./crypto/aes"
	"./crypto/rsa"
	"./crypto/serpent"
	"./crypto/xor"
	"github.com/fatih/color"
)

const (
	EncryptionNormal  = 0xA9
	EncryptionHard    = 0xBA
	EncryptionExtreme = 0x90
	CompressionNone   = 0xF2
	CompressionZIP    = 0x88
	CompressionLZMA   = 0xC7
)

var FileKey = []byte{0x33, 0x5c, 0xb3, 0x80, 0x2c, 0x86, 0x92, 0x27, 0xc0, 0xbf, 0xc3, 0x9d, 0xad, 0x8e, 0x54, 0xc4, 0x63, 0x6d, 0xb8, 0x9d, 0xc4, 0x95, 0xed, 0x9c, 0x4a, 0x33, 0x96, 0xde, 0x06, 0xc0, 0x4d, 0xda}

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

func EncryptUSB(path string, rsaKeys rsa.RSAKeys, encryptionMethod byte, compressionMethod byte, rawPassword string, iv []byte) {
	fileList := []string{}
	hashedPassword := sha256.Sum256([]byte(rawPassword))
	err := filepath.Walk(path, func(path string, f os.FileInfo, err error) error {
		fileList = append(fileList, path)
		return nil
	})
	if err != nil {
		Debug("Error when getting files", Error)
		os.Exit(0)
	}
	count := len(fileList)
	i := 0
	countError := 0
	for _, file := range fileList {
		name := filepath.Base(file)
		if !IsBlacklisted(name) {
			err := EncryptUSBFile(file, encryptionMethod, rsaKeys, compressionMethod, hashedPassword[:])
			if err != nil {
				countError++
			} else {
				i++
			}
			fmt.Printf("\r	%s %d/%d files are encrypted", color.HiYellowString("⚡"), i, count)
		} else {
			count--
		}
	}
	fmt.Println()
	Debug("All your files have been encrypted !", Success)
	Debug("Errors: "+string(countError), Error)
}

func DecryptUSB(path string, config Config, rawPassword string) {
	fileList := []string{}
	hashedPassword := sha256.Sum256([]byte(rawPassword))
	prKey, pbKey, err := GetRSAKeys(config.PublicKey, config.PrivateKey)
	if err != nil {
		Debug("Error when getting RSA keys", Error)
		os.Exit(0)
	}
	rsaKeys := rsa.RSAKeys{Bits: int(config.KeyBits), PrivateKey: prKey, PublicKey: pbKey}
	err = filepath.Walk(path, func(path string, f os.FileInfo, err error) error {
		name := filepath.Base(path)
		b, _ := ioutil.ReadFile(path)
		if !IsBlacklisted(name) && IsEncrypted(b) {
			fileList = append(fileList, path)
		}
		return nil
	})
	if err != nil {
		Debug("Error when getting files...", Error)
		os.Exit(0)
	}
	count := len(fileList)
	i := 0
	countError := 0
	for _, file := range fileList {
		err := DecryptUSBFile(file, rsaKeys, hashedPassword[:])
		if err != nil {
			countError++
		} else {
			i++
		}
		fmt.Printf("\r	%s %d/%d files are decrypted", color.HiYellowString("⚡"), i, count)
	}
	fmt.Println()
	Debug("All your files have been decrypted !", Success)
	Debug("Errors: "+string(countError), Error)
}

func EncryptUSBFile(fileName string, encryptionMethod byte, rsaKeys rsa.RSAKeys, compressionMethod byte, hashedPassword []byte) error {
	b, err := ioutil.ReadFile(fileName)
	if err != nil {
		return err
	}
	var file File
	key := xor.XorKey{Key: XorKeyBA}
	file.Header = string(key.Encrypt([]byte("CookieUSB")))
	key = xor.XorKey{Key: ReverseByteArray(XorKeyBA)}
	encryptedName := string(key.Encrypt([]byte(filepath.Base(fileName))))
	file.Name = encryptedName
	file.EncryptionMethod = encryptionMethod
	file.CompressionMethod = compressionMethod
	fKey, _ := GenerateKey()
	encryptedKey, err := rsaKeys.Encrypt(fKey)
	if err != nil {
		return err
	}
	fIV, _ := GenerateIV()
	file.IV = fIV
	var encryptedData []byte
	var err2 error
	switch encryptionMethod {
	case EncryptionNormal:
		file.Key = encryptedKey
		aesK := aes.AESKey{Key: fKey, IV: fIV}
		encryptedData, err2 = aesK.Encrypt(b)
		if err2 != nil {
			return err2
		}
	case EncryptionHard:
		file.Key = encryptedKey
		serpentKey, err := serpent.NewCipher(fKey)
		if err != nil {
			return err
		}
		serpentKey.Encrypt(encryptedData, b)
	case EncryptionExtreme:
		serpentKey, err := serpent.NewCipher(hashedPassword)
		if err != nil {
			return err
		}
		serpentKey.Encrypt(encryptedKey, encryptedKey)
		file.Key = encryptedKey
		hKey := sha256.Sum256(fKey)
		sKey := sha256.Sum256(append(hKey[:], hashedPassword...))
		serpentKey, err = serpent.NewCipher(sKey[:])
		if err != nil {
			return err
		}
		aesK := aes.AESKey{Key: fKey, IV: fIV}
		encryptedData, err = aesK.Encrypt(b)
		serpentKey.Encrypt(encryptedData, encryptedData)
	}

	switch compressionMethod {
	case CompressionZIP:
		compressedData, err := gzip.Compress(encryptedData)
		if err != nil {
			return err
		}
		file.Data = compressedData
	case CompressionLZMA:
		compressedData, err := lzma.Compress(encryptedData)
		if err != nil {
			return err
		}
		file.Data = compressedData
	}

	serialized, err := SerializeFile(file)
	if err != nil {
		return err
	}
	key = xor.XorKey{Key: FileKey}
	serialized = key.Encrypt(serialized)

	filename := fileName
	if encryptionMethod == EncryptionExtreme {
		path, err := filepath.Abs(fileName)
		if err != nil {
			return err
		}
		hName := sha256.Sum256([]byte(filepath.Base(fileName)))
		name := string(hName[:])
		filename = path + name
		os.Rename(fileName, filename)
	}
	err = ioutil.WriteFile(filename, serialized, 0644)
	return err
}

func DecryptUSBFile(fileName string, rsaKeys rsa.RSAKeys, hashedPassword []byte) error {
	b, err := ioutil.ReadFile(fileName)
	if err != nil {
		return err
	}
	key := xor.XorKey{Key: FileKey}
	decryptedData := key.Decrypt(b)
	file, err := DeserializeAsFile(decryptedData)
	key = xor.XorKey{Key: ReverseByteArray(XorKeyBA)}
	decryptedName := string(key.Decrypt([]byte(file.Name)))
	file.Name = decryptedName

	switch file.CompressionMethod {
	case CompressionZIP:
		uncompressedData, err := gzip.Uncompress(file.Data)
		if err != nil {
			return err
		}
		file.Data = uncompressedData
	case CompressionLZMA:
		uncompressedData, err := lzma.Compress(file.Data)
		if err != nil {
			return err
		}
		file.Data = uncompressedData
	}

	switch file.EncryptionMethod {
	case EncryptionNormal:
		decryptedKey, err := rsaKeys.Decrypt(file.Key)
		if err != nil {
			return err
		}
		file.Key = decryptedKey
		aesK := aes.AESKey{Key: file.Key, IV: file.IV}
		file.Data, err = aesK.Decrypt(file.Data)
	case EncryptionHard:
		decryptedKey, err := rsaKeys.Decrypt(file.Key)
		if err != nil {
			return err
		}
		file.Key = decryptedKey
		serpentKey, err := serpent.NewCipher(file.Key)
		if err != nil {
			return err
		}
		serpentKey.Decrypt(file.Data, file.Data)
	case EncryptionExtreme:
		serpentKey, err := serpent.NewCipher(hashedPassword)
		if err != nil {
			return err
		}
		serpentKey.Decrypt(file.Key, file.Key)
		hKey := sha256.Sum256(file.Key)
		sKey := sha256.Sum256(append(hKey[:], hashedPassword...))
		serpentKey, err = serpent.NewCipher(sKey[:])
		serpentKey.Decrypt(file.Data, file.Data)
		aesK := aes.AESKey{Key: file.Key, IV: file.IV}
		file.Data, err = aesK.Decrypt(file.Data)
		if err != nil {
			return err
		}
	}

	filename := fileName
	if file.EncryptionMethod == EncryptionExtreme {
		path, err := filepath.Abs(fileName)
		if err != nil {
			return err
		}
		filename = path + file.Name
		os.Rename(fileName, filename)
	}
	err = ioutil.WriteFile(filename, file.Data, 0644)
	return err
}
