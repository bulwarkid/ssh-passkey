package main

import "fmt"

func checkErr(err error, msg string) {
	if err != nil {
		panic(fmt.Sprintf("Error: %s - %s", err, msg))
	}
}
