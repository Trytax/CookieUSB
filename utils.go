package main

import (
	"fmt"

	"github.com/fatih/color"
)

const (
	Success = iota
	Error
	Warning
	Task
	Normal
)

func Debug(message string, level int) {
	switch level {
	case Success:
		fmt.Println(color.GreenString("[+]"), message)
	case Error:
		fmt.Println(color.RedString("[-]"), message)
	case Warning:
		fmt.Println(color.YellowString("[!]"), message)
	case Task:
		fmt.Println(color.CyanString("[~]"), message)
	case Normal:
		fmt.Println(color.MagentaString("[*]"), message)
	}
}
