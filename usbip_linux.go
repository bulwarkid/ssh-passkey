//go:build linux

package main

import (
	"os/exec"
)

func usbipCommand() *exec.Cmd {
	return exec.Command("sudo", "usbip", "attach", "-r", "127.0.0.1", "-b", "2-2")
}
