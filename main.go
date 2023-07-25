package main

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"fmt"
	"io"
	"os"

	virtual_fido "github.com/bulwarkid/virtual-fido"
	"github.com/bulwarkid/virtual-fido/cose"
	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"
)

var keyFilename string

func start(cmd *cobra.Command, args []string) {
	if keyFilename == "" {
		fmt.Println("No key specified")
		return
	}
	keyFile, err := os.Open(keyFilename)
	if err != nil {
		fmt.Println("Could not find key file")
		return
	}
	defer keyFile.Close()
	keyBytes, err := io.ReadAll(keyFile)
	if err != nil {
		fmt.Println("Could not read key file")
		return
	}
	key, err := ssh.ParseRawPrivateKey(keyBytes)
	coseKey := cose.SupportedCOSEPrivateKey{}
	if ecdsaKey, ok := key.(*ecdsa.PrivateKey); ok {
		coseKey.ECDSA = ecdsaKey
	} else if ed25519Key, ok := key.(*ed25519.PrivateKey); ok {
		coseKey.Ed25519 = ed25519Key
	} else if rsaKey, ok := key.(*rsa.PrivateKey); ok {
		coseKey.RSA = rsaKey
	} else {
		fmt.Println("Unsupported key format. This application only supports ECDSA, Ed25519, and RSA private keys.")
		return
	}
	client := NewSSHFIDOClient(&coseKey)
	virtual_fido.SetLogOutput(os.Stdout)
	done := make(chan bool)
	go func() {
		virtual_fido.Start(client)
		done <- true
	}()
	go func() {
		prog := usbipCommand()
		prog.Stdin = os.Stdin
		prog.Stdout = os.Stdout
		prog.Stderr = os.Stderr
		err := prog.Run()
		if err != nil {
			fmt.Printf("Error: %s\n", err)
		}
		done <- true
	}()
	<-done
	<-done
}

var rootCmd = &cobra.Command{
	Use:   "ssh_passkey",
	Short: "Create a FIDO authenticator using an SSH key",
	Long:  `ssh_passkey allows you to use your SSH key for the keys in CTAP2 for WebAuthN/Passkeys`,
}

func init() {
	start := &cobra.Command{
		Use:   "start",
		Short: "Start up FIDO device",
		Run:   start,
	}
	rootCmd.PersistentFlags().StringVar(&keyFilename, "key", "", "SSH private key to use")
	rootCmd.MarkFlagRequired("key")
	rootCmd.AddCommand(start)
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
