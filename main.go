package main

import (
	"encoding/base64"

	"fmt"

	"net/http"

	"io/ioutil"

	"os"

	"github.com/fatih/color"
)

const (
	logoB64 = "IF9fX18gICAgICAgICAgICAgICAgICAgIF9fICAgICAgICAgICAgICAgICAgX18gIF9fICBfX19fICAgIF9fX18gICAgICANCi9cICBfYFwgICAgICAgICAgICAgICAgIC9cIFwgICAgICBfXyAgICAgICAgL1wgXC9cIFwvXCAgX2BcIC9cICBfYFwgICAgDQpcIFwgXC9cX1wgICAgX19fICAgICBfX19cIFwgXC8nXCAvXF9cICAgICBfX1wgXCBcIFwgXCBcLFxMXF9cIFwgXExcIFwgIA0KIFwgXCBcL18vXyAgLyBfX2BcICAvIF9fYFwgXCAsIDwgXC9cIFwgIC8nX19gXCBcIFwgXCBcL19cX18gXFwgXCAgXyA8JyANCiAgXCBcIFxMXCBcL1wgXExcIFwvXCBcTFwgXCBcIFxcYFxcIFwgXC9cICBfXy9cIFwgXF9cIFwvXCBcTFwgXCBcIFxMXCBcDQogICBcIFxfX19fL1wgXF9fX18vXCBcX19fXy9cIFxfXCBcX1wgXF9cIFxfX19fXFwgXF9fX19fXCBgXF9fX19cIFxfX19fLw0KICAgIFwvX19fLyAgXC9fX18vICBcL19fXy8gIFwvXy9cL18vXC9fL1wvX19fXy8gXC9fX19fXy9cL19fX19fL1wvX19fLyANCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg"
	version = "1.0.0"
)

func checkForUpdates() (bool, string) {
	response, err := http.Get("https://raw.githubusercontent.com/Trytax/CookieUSB/master/main.go")
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

func main() {
	// Print logo
	color.Set(color.FgHiYellow)
	l, _ := base64.StdEncoding.DecodeString(logoB64)
	fmt.Println(string(l))
	color.Unset()

	Debug("Created by Trytax https://github.com/Trytax/CookieUSB", Normal)
	Debug("Checking for updates...", Task)

	tf, b := checkForUpdates()
	if tf {
		Debug("You are up-to-date. Version="+version, Success)
	} else {
		Debug("There is a new version ! ("+b+"). Please download it on: https://github.com/Trytax/CookieUSB", Error)
		os.Exit(0)
	}
}
