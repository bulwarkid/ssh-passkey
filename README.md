# SSH Passkey

ssh_passkey is a utility to enable you to use an SSH key as a passkey for authenticating with websites. It is built on top of [VirtualFIDO](https://github.com/bulwarkid/virtual-fido), a project that lets you create a virtual USB FIDO device for use with WebAuthN.

Note: this utility uses your public key as the public key for the passkey, so if you don't want to send your public key to a website do not use this with that website.

## Limitations

VirtualFIDO relies on USB/IP to create the virtual USB device, so that library is limited to Windows/Linux right now. Mac support is in development, but Mac virtual USB drivers require an App to install so it might be hard to add Mac support to this utility.

This utility supports ECDSA, Ed25519, and RSA keys, but many websites only support ECDSA keys, so you may need to use one of those.

## Usage

If you wish to test this utility, [Yubico's WebAuthN test page](https://demo.yubico.com/webauthn-technical/registration) is fairly good and verified to work with ssh_passkey (at least with ECDSA keys).

### Windows

1. `.\usbip\bin\usbip.exe install`
2. `go run . start --key=<path_to_private_key>`

### Linux

1. `sudo modprobe vhci-hcd`
2. `go run . start --key=<path_to_private_key>`
