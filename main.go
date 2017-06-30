package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"log"
	"math"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"

	"crypto/rsa"

	"./crypto/aes"
	"./crypto/xor"
	"github.com/fatih/color"
	"github.com/nbutton23/zxcvbn-go"
	"golang.org/x/crypto/bcrypt"
)

const (
	logoB64    = "IF9fX18gICAgICAgICAgICAgICAgICAgIF9fICAgICAgICAgICAgICAgICAgX18gIF9fICBfX19fICAgIF9fX18gICAgICANCi9cICBfYFwgICAgICAgICAgICAgICAgIC9cIFwgICAgICBfXyAgICAgICAgL1wgXC9cIFwvXCAgX2BcIC9cICBfYFwgICAgDQpcIFwgXC9cX1wgICAgX19fICAgICBfX19cIFwgXC8nXCAvXF9cICAgICBfX1wgXCBcIFwgXCBcLFxMXF9cIFwgXExcIFwgIA0KIFwgXCBcL18vXyAgLyBfX2BcICAvIF9fYFwgXCAsIDwgXC9cIFwgIC8nX19gXCBcIFwgXCBcL19cX18gXFwgXCAgXyA8JyANCiAgXCBcIFxMXCBcL1wgXExcIFwvXCBcTFwgXCBcIFxcYFxcIFwgXC9cICBfXy9cIFwgXF9cIFwvXCBcTFwgXCBcIFxMXCBcDQogICBcIFxfX19fL1wgXF9fX18vXCBcX19fXy9cIFxfXCBcX1wgXF9cIFxfX19fXFwgXF9fX19fXCBgXF9fX19cIFxfX19fLw0KICAgIFwvX19fLyAgXC9fX18vICBcL19fXy8gIFwvXy9cL18vXC9fL1wvX19fXy8gXC9fX19fXy9cL19fX19fL1wvX19fLyANCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg"
	version    = "1.0.0"
	configName = "95cdad2dcf2dab6693609469dda29513ff18183d494f2bccdb1e7b8b8d03f813556e92bac864775083399cb083cc728bd2b4805fcc88cbc447dec31847a172a1" // Whirlpool("CookieUSB.config")
)

// CheckForUpdates : Check if the program is up-to-date
func CheckForUpdates() (bool, string) {
	response, err := http.Get("https://raw.githubusercontent.com/Trytax/CookieUSB/master/version.txt")
	if err != nil {
		Debug("Error when trying to check for updates", Error)
	}
	defer response.Body.Close()

	body, err := ioutil.ReadAll(response.Body)
	if string(body) != version {
		return false, string(body)
	}
	return true, version
}

// https://github.com/deepakjois/gousbdrivedetector/blob/master/usbdrivedetector_linux.go

// Detect : Return a list of USB drives
func Detect() ([]string, error) {
	var drives []string
	driveMap := make(map[string]bool)
	dfPattern := regexp.MustCompile("^(\\/[^ ]+)[^%]+%[ ]+(.+)$")

	cmd := "df"
	out, err := exec.Command(cmd).Output()

	if err != nil {
		log.Printf("Error calling df: %s", err)
	}

	s := bufio.NewScanner(bytes.NewReader(out))
	for s.Scan() {
		line := s.Text()
		if dfPattern.MatchString(line) {
			device := dfPattern.FindStringSubmatch(line)[1]
			rootPath := dfPattern.FindStringSubmatch(line)[2]

			if ok := isUSBStorage(device); ok {
				driveMap[rootPath] = true
			}
		}
	}

	for k := range driveMap {
		_, err := os.Open(k)
		if err == nil {
			drives = append(drives, k)
		}
	}

	return drives, nil
}

// isUSBStorage : Check if it is a USB Storage
func isUSBStorage(device string) bool {
	deviceVerifier := "ID_USB_DRIVER=usb-storage"
	cmd := "udevadm"
	args := []string{"info", "-q", "property", "-n", device}
	out, err := exec.Command(cmd, args...).Output()

	if err != nil {
		log.Printf("Error checking device %s: %s", device, err)
		return false
	}

	if strings.Contains(string(out), deviceVerifier) {
		return true
	}

	return false
}

func main() {
	fmt.Print("\033[2J") // Clear console
	// Print logo
	color.Set(color.FgHiYellow)
	l, _ := base64.StdEncoding.DecodeString(logoB64)
	fmt.Println(string(l))
	color.Unset()

	Debug("Created by Trytax https://github.com/Trytax/CookieUSB", Normal)
	Debug("Checking for updates...", Task)

	tf, b := CheckForUpdates()
	if tf {
		Debug("You are up-to-date. Version="+version, Success)
	} else {
		Debug("There is a new version ! ("+b+"). Please download it on: https://github.com/Trytax/CookieUSB", Error)
		//os.Exit(0)
	}

	Debug("Getting USB drives...", Task)
	drives, err := Detect()
	if err == nil {
		Debug(strconv.Itoa(len(drives))+" USB devices found:", Success)
		for _, d := range drives {
			fmt.Println(d)
		}
	} else {
		Debug("Error when getting USB drives", Error)
		os.Exit(0)
	}

	var input string
	for !Contains(input, drives) {
		Debug("Please enter a USB drive path:", Normal)
		fmt.Scanln(&input)
	}

	Debug("Checking if the USB drive is encrypted...", Task)
	config, err := GetConfig(input)
	isEncrypted := false
	if err == nil {
		isEncrypted = config.IsEncrypted
	}
	if isEncrypted {
		Debug("The USB is encrypted", Warning)
		var answer string
		for answer != "y" {
			Debug("Do you want to decrypt it ? (y/n)", Normal)
			fmt.Scanln(&answer)
			if answer == "n" {
				os.Exit(0)
			}
		}

		var rawPassword string
		for bcrypt.CompareHashAndPassword([]byte(config.Password), []byte(rawPassword)) != nil {
			Debug("Please enter the password:", Normal)
			fmt.Scanln(&rawPassword)
		}
		hashedPassword := sha256.Sum256([]byte(rawPassword))
		aesKey := aes.AESKey{Key: hashedPassword[:], IV: config.IV}
		DecryptConfig(config, aesKey)
		// TODO : Decrypt all the files
	} else {
		Debug("The USB is not encrypted", Warning)
		var answer string
		for answer != "y" {
			Debug("Do you want to encrypt it ? (y/n)", Normal)
			fmt.Scanln(&answer)
			if answer == "n" {
				os.Exit(0)
			}
		}
		var rawPassword string
		for {
			Debug("Please enter a password:", Normal)
			fmt.Scanln(&rawPassword)
			strength := zxcvbn.PasswordStrength(rawPassword, nil)
			if strength.Score <= 2 {
				Debug("Your password is weak !", Error)
			} else {
				Debug("Your password is strong", Success)
				break
			}
		}
		Debug("Hashing password...", Task)
		hashed, err := bcrypt.GenerateFromPassword([]byte(rawPassword), 12)
		if err != nil {
			Debug("Impossible to hash your password", Error)
			os.Exit(0)
		}
		Debug("Hashed password : "+string(hashed), Success)
		var userConfig Config
		key := xor.XorKey{Key: ReverseByteArray(XorKeyBA)}
		userConfig.Password = string(key.Encrypt(hashed))

		Debug("Generating IV...", Task)
		iv, err := GenerateIV()
		if err != nil {
			Debug("Impossible to generate a IV", Error)
			os.Exit(0)
		}
		userConfig.IV = iv
		Debug("B64-IV : "+base64.StdEncoding.EncodeToString(iv), Success)

		var bits string
		result := false
		for !result {
			Debug("Please enter the RSA-key-size (bits):", Normal)
			fmt.Scanln(&bits)

			f, err := strconv.ParseFloat(bits, 64)
			if err != nil {
				Debug("Enter a valid number !", Error)
			} else {
				val := math.Log2(f)
				if val == math.Floor(val) {
					result = true
				} else {
					result = false
				}
			}
		}
		i, _ := strconv.ParseInt(bits, 10, 16)
		userConfig.KeyBits = int16(i)
		Debug("Generating RSA-"+bits+" keys...", Task)
		rsaKeys, err := rsa.GenerateKey(rand.Reader, int(i))
		if err != nil {
			Debug("Error when generating RSA keys", Error)
			os.Exit(0)
		}
		Debug("The RSA-"+bits+" keys are generated", Success)
		prKey, pbKey, err := GetPEMKey(rsaKeys)
		if err != nil {
			Debug("Error when converting RSA keys to string", Error)
			os.Exit(0)
		}
		hashedPassword := sha256.Sum256([]byte(rawPassword))
		aesKey := aes.AESKey{Key: hashedPassword[:], IV: userConfig.IV}
		Debug("Encrypting the keys...", Task)
		encryptedPrKey, err := aesKey.Encrypt([]byte(prKey))
		if err != nil {
			Debug("Error when encrypting Private Key", Error)
			os.Exit(0)
		}
		encryptedPbKey, err := aesKey.Encrypt([]byte(pbKey))
		if err != nil {
			Debug("Error when encrypting Public Key", Error)
			os.Exit(0)
		}
		Debug("The keys are encrypted", Success)
		/*generateLog := false
		Debug("Do you want to generate a log file ? (y/n)", Normal)
		fmt.Scanln(&input)
		if input == "y" {
			generateLog = true
		}*/
		userConfig.PublicKey = encryptedPbKey
		userConfig.PrivateKey = encryptedPrKey
		userConfig.IsEncrypted = true
		key = xor.XorKey{Key: XorKeyBA}
		userConfig.Header = string(key.Encrypt([]byte("CookieUSB")))
		convertedConfig, err := SerializeConfig(userConfig)
		if err != nil {
			Debug("Error when serializing Config", Error)
			log.Fatal(err)
			os.Exit(0)
		}
		err = ioutil.WriteFile(input+"/"+configName, convertedConfig, 0644)
		if err != nil {
			Debug("Error when creating the config file", Error)
			os.Exit(0)
		}
		Debug("The config file is created !", Success)
		Debug("Encrypting your files...", Task)
	}
}
