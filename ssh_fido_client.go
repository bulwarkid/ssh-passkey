package main

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/bulwarkid/virtual-fido/cose"
	crypto "github.com/bulwarkid/virtual-fido/crypto"
	"github.com/bulwarkid/virtual-fido/identities"
	webauthn "github.com/bulwarkid/virtual-fido/webauthn"
	"github.com/fxamacker/cbor/v2"
	"golang.org/x/crypto/hkdf"
)

type SSHFIDOClient struct {
	privateKey           *cose.SupportedCOSEPrivateKey
	encryptionKey        []byte
	certificateAuthority *x509.Certificate
	caPrivateKey         *cose.SupportedCOSEPrivateKey
}

func NewSSHFIDOClient(privateKey *cose.SupportedCOSEPrivateKey) *SSHFIDOClient {
	caPrivateKey := privateKey
	certificateAuthority, err := identities.CreateSelfSignedCA(privateKey)
	checkErr(err, "Could not create CA")
	privateKeyBytes := cose.MarshalCOSEPrivateKey(privateKey)
	encryptionKey := generateDerivedBytes(privateKeyBytes, []byte("symmetric-encryption-key"), 32)
	return &SSHFIDOClient{
		privateKey:           privateKey,
		encryptionKey:        encryptionKey,
		certificateAuthority: certificateAuthority,
		caPrivateKey:         caPrivateKey,
	}
}

func (client *SSHFIDOClient) SupportsResidentKey() bool {
	return false
}

func (client *SSHFIDOClient) NewCredentialSource(
	pubKeyCredParams []webauthn.PublicKeyCredentialParams,
	excludeList []webauthn.PublicKeyCredentialDescriptor,
	relyingParty *webauthn.PublicKeyCredentialRPEntity,
	user *webauthn.PublicKeyCrendentialUserEntity) *identities.CredentialSource {
	source := &identities.CredentialSource{
		Type:             "public-key",
		ID:               []byte{}, // To be filled in later
		PrivateKey:       client.privateKey,
		RelyingParty:     relyingParty,
		User:             user,
		SignatureCounter: 0,
	}
	encodedSource := encodeCredentialSource(source, client.encryptionKey)
	source.ID = encodedSource
	fmt.Printf("ID: %#v\n", source.ID)
	return source
}
func (client *SSHFIDOClient) GetAssertionSource(relyingPartyID string, allowList []webauthn.PublicKeyCredentialDescriptor) *identities.CredentialSource {
	var source *identities.CredentialSource = nil
	var err error = nil
	for _, descriptor := range allowList {
		source, err = decodeCredentialSource(descriptor.ID, client.encryptionKey)
		fmt.Printf("Err: %s\n", err)
		if err == nil {
			if source.RelyingParty.ID == relyingPartyID {
				break
			}
		}
	}
	return source
}

func (client *SSHFIDOClient) CreateAttestationCertificiate(privateKey *cose.SupportedCOSEPrivateKey) []byte {
	cert, err := identities.CreateSelfSignedAttestationCertificate(client.certificateAuthority, client.caPrivateKey, privateKey)
	checkErr(err, "Could not create attestation certificate")
	return cert.Raw
}

// User Approvals

func prompt(prompt string) string {
	fmt.Println(prompt)
	fmt.Print("-->")
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Scan()
	return scanner.Text()
}

func (client *SSHFIDOClient) ApproveAccountCreation(relyingParty string) bool {
	answer := prompt(fmt.Sprintf("Use SSH key for an account at %s? (Y/n)", relyingParty))
	return strings.ToLower(answer) == "y"
}
func (client *SSHFIDOClient) ApproveAccountLogin(credentialSource *identities.CredentialSource) bool {
	answer := prompt(fmt.Sprintf("Use SSH key to login to %s? (Y/n)", credentialSource.RelyingParty.Name))
	return strings.ToLower(answer) == "y"
}
func (client *SSHFIDOClient) ApproveU2FRegistration(keyHandle *webauthn.KeyHandle) bool {
	answer := prompt("Create U2F account encrypted with SSH key? (Y/n)")
	return strings.ToLower(answer) == "y"
}
func (client *SSHFIDOClient) ApproveU2FAuthentication(keyHandle *webauthn.KeyHandle) bool {
	answer := prompt("Approve U2F Authentication encrypted with SSH key? (Y/n)")
	return strings.ToLower(answer) == "y"
}

// U2F Methods
func (client *SSHFIDOClient) SealingEncryptionKey() []byte {
	return client.encryptionKey
}
func (client *SSHFIDOClient) NewPrivateKey() *ecdsa.PrivateKey {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	checkErr(err, "Could not generate private key")
	return privateKey
}
func (client *SSHFIDOClient) NewAuthenticationCounterId() uint32 {
	// Not implemented, just return 0
	return 0
}

// Unsupported PIN functions
func (client *SSHFIDOClient) SupportsPIN() bool {
	return false
}
func (client *SSHFIDOClient) PINHash() []byte {
	return nil
}
func (client *SSHFIDOClient) SetPINHash(pin []byte) {}
func (client *SSHFIDOClient) PINRetries() int32 {
	return 0
}
func (client *SSHFIDOClient) SetPINRetries(retries int32) {}
func (client *SSHFIDOClient) PINKeyAgreement() *crypto.ECDHKey {
	return nil
}
func (client *SSHFIDOClient) PINToken() []byte {
	return nil
}

func generateDerivedBytes(inputSecret []byte, info []byte, n int) []byte {
	byteReader := generateDerivedByteReader(inputSecret, info)
	outputSecret := make([]byte, n)
	_, err := io.ReadFull(byteReader, outputSecret)
	checkErr(err, "Could not generate derived secret bytes")
	return outputSecret
}

func generateDerivedByteReader(inputSecret []byte, info []byte) io.Reader {
	return hkdf.New(sha256.New, inputSecret, nil, info)
}

func derivePrivateKey(privateKey *ecdsa.PrivateKey, info []byte) *ecdsa.PrivateKey {
	privateKeyBytes, err := x509.MarshalECPrivateKey(privateKey)
	checkErr(err, "Could not marshal private key")
	byteReader := generateDerivedByteReader(privateKeyBytes, info)
	derivedKey, err := ecdsa.GenerateKey(elliptic.P256(), byteReader)
	checkErr(err, "Could not derive key")
	return derivedKey
}

type encodedCredentialSource struct {
	PrivateKey   []byte                                  `cbor:"0,keyasint"`
	RelyingParty webauthn.PublicKeyCredentialRPEntity    `cbor:"1,keyasint"`
	User         webauthn.PublicKeyCrendentialUserEntity `cbor:"2,keyasint"`
}

func encodeCredentialSource(source *identities.CredentialSource, key []byte) []byte {
	privateKeyBytes := cose.MarshalCOSEPrivateKey(source.PrivateKey)
	encodedSource := encodedCredentialSource{PrivateKey: privateKeyBytes, RelyingParty: *source.RelyingParty, User: *source.User}
	fmt.Printf("Encoded source: %#v\n\n", encodedSource)
	sourceBytes := MarshalCBOR(&encodedSource)
	fmt.Printf("Source bytes: %#v\n\n", sourceBytes)
	box := crypto.Seal(key, sourceBytes)
	encryptedBytes := MarshalCBOR(box)
	return encryptedBytes
}

func decodeCredentialSource(sourceBytes []byte, key []byte) (*identities.CredentialSource, error) {
	box := crypto.EncryptedBox{}
	err := cbor.Unmarshal(sourceBytes, &box)
	if err != nil {
		return nil, err
	}
	decryptedBytes := crypto.Open(key, box)
	decodedSource := encodedCredentialSource{}
	err = cbor.Unmarshal(decryptedBytes, &decodedSource)
	if err != nil {
		return nil, err
	}
	fmt.Printf("Decoded source: %#v\n", decodedSource)
	privateKey, err := cose.UnmarshalCOSEPrivateKey(decodedSource.PrivateKey)
	if err != nil {
		return nil, err
	}
	return &identities.CredentialSource{
		Type:             "public-key",
		ID:               sourceBytes,
		PrivateKey:       privateKey,
		RelyingParty:     &decodedSource.RelyingParty,
		User:             &decodedSource.User,
		SignatureCounter: 0,
	}, nil
}

func MarshalCBOR(val interface{}) []byte {
	encOptions := cbor.CTAP2EncOptions()
	encMode, err := encOptions.EncMode()
	checkErr(err, "Could not get encoding mode")
	data, err := encMode.Marshal(val)
	checkErr(err, "Could not marshal CBOR")
	return data
}
