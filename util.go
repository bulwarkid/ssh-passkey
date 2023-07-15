package sshpasskey

import "fmt"

func checkErr(err error, msg string) {
	if (err != nil) {
		panic(fmt.Sprintf("Error: %w - %s", err, msg))
	}
}