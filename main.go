package main

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"

	"github.com/fatih/color"
)

const (
	logoB64 = "IF9fX18gICAgICAgICAgICAgICAgICAgIF9fICAgICAgICAgICAgICAgICAgX18gIF9fICBfX19fICAgIF9fX18gICAgICANCi9cICBfYFwgICAgICAgICAgICAgICAgIC9cIFwgICAgICBfXyAgICAgICAgL1wgXC9cIFwvXCAgX2BcIC9cICBfYFwgICAgDQpcIFwgXC9cX1wgICAgX19fICAgICBfX19cIFwgXC8nXCAvXF9cICAgICBfX1wgXCBcIFwgXCBcLFxMXF9cIFwgXExcIFwgIA0KIFwgXCBcL18vXyAgLyBfX2BcICAvIF9fYFwgXCAsIDwgXC9cIFwgIC8nX19gXCBcIFwgXCBcL19cX18gXFwgXCAgXyA8JyANCiAgXCBcIFxMXCBcL1wgXExcIFwvXCBcTFwgXCBcIFxcYFxcIFwgXC9cICBfXy9cIFwgXF9cIFwvXCBcTFwgXCBcIFxMXCBcDQogICBcIFxfX19fL1wgXF9fX18vXCBcX19fXy9cIFxfXCBcX1wgXF9cIFxfX19fXFwgXF9fX19fXCBgXF9fX19cIFxfX19fLw0KICAgIFwvX19fLyAgXC9fX18vICBcL19fXy8gIFwvXy9cL18vXC9fL1wvX19fXy8gXC9fX19fXy9cL19fX19fL1wvX19fLyANCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg"
	version = "1.0.0"
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

// Contains : Check if the string is in the array
func Contains(s string, list []string) bool {
	for _, e := range list {
		if e == s {
			return true
		}
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
		os.Exit(0)
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
}
