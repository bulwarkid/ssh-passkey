//go:build windows

package main

import (
	"os/exec"
)

func usbipCommand() *exec.Cmd {
	command := exec.Command(".\\usbip.exe", "attach", "-r", "127.0.0.1", "-b", "2-2")
	command.Dir = ".\\usbip\\bin"
	return command
}
