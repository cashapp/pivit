package main

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"

	"github.com/cashapp/pivit/cmd/pivit/utils"
	"github.com/go-piv/piv-go/piv"
	"github.com/pkg/errors"
)

// commandGenerate generates a new keypair and certificate signing request
func commandGenerate() error {
	cards, err := piv.Cards()
	if err != nil {
		return errors.Wrap(err, "enumerate smart cards")
	}
	if len(cards) != 1 {
		return errors.New("no smart card found")
	}

	yk, err := piv.Open(cards[0])
	if err != nil {
		return errors.Wrap(err, "open smart card")
	}
	defer func() {
		_ = yk.Close()
	}()

	pin, err := utils.GetPin()
	if err != nil {
		return errors.Wrap(err, "get pin")
	}

	managementKey := deriveManagementKey(pin)
	key := piv.Key{
		Algorithm:   piv.AlgorithmEC384,
		PINPolicy:   piv.PINPolicyNever,
		TouchPolicy: piv.TouchPolicyAlways,
	}
	publicKey, err := yk.GenerateKey(*managementKey, piv.SlotAuthentication, key)
	if err != nil {
		return errors.Wrap(err, "generate new key")
	}

	deviceCert, err := yk.AttestationCertificate()
	if err != nil {
		return errors.Wrap(err, "device cert")
	}
	fmt.Println("Printing Yubikey device attestation certificate:")
	printCertificate(deviceCert)

	keyCert, err := yk.Attest(piv.SlotAuthentication)
	if err != nil {
		return errors.Wrap(err, "attest key")
	}
	fmt.Println("Printing generated key certificate:")
	printCertificate(keyCert)
	err = yk.SetCertificate(*managementKey, piv.SlotAuthentication, keyCert)
	if err != nil {
		return errors.Wrap(err, "set yubikey certificate")
	}

	auth := piv.KeyAuth{
		PINPolicy: piv.PINPolicyOnce,
		PINPrompt: func() (string, error) {
			fmt.Println("Touch Yubikey now to sign your key...")
			return pin, nil
		},
	}
	privateKey, err := yk.PrivateKey(piv.SlotAuthentication, publicKey, auth)
	if err != nil {
		return errors.Wrap(err, "access private key")
	}
	attestation, err := piv.Verify(deviceCert, keyCert)
	if err != nil {
		return errors.Wrap(err, "verify device certificate")
	}
	certRequest, err := certificateRequest(strconv.FormatUint(uint64(attestation.Serial), 10), privateKey)
	fmt.Println("Printing certificate signing request:")
	printCsr(certRequest)

	_ = yk.Close()
	return nil
}

func deriveManagementKey(pin string) *[24]byte {
	hash := crypto.SHA256.New()
	sha1 := hash.Sum([]byte(pin))
	var mk [24]byte
	copy(mk[:], sha1[:24])
	return &mk
}

func certificateRequest(serialNumber string, privateKey crypto.PrivateKey) ([]byte, error) {
	emailAddress := os.Getenv("PIVIT_EMAIL")
	pivitOrg := strings.Split(os.Getenv("PIVIT_ORG"), ",")
	pivitOrgUnit := strings.Split(os.Getenv("PIVIT_ORG_UNIT"), ",")
	subject := pkix.Name{
		Organization:       pivitOrg,
		OrganizationalUnit: pivitOrgUnit,
		SerialNumber:       serialNumber,
		CommonName:         emailAddress,
	}
	certRequest := &x509.CertificateRequest{
		SignatureAlgorithm: x509.ECDSAWithSHA256,
		Subject:            subject,
		DNSNames:           []string{},
		EmailAddresses:     []string{emailAddress},
		IPAddresses:        []net.IP{},
		URIs:               []*url.URL{},
		ExtraExtensions:    []pkix.Extension{},
	}

	csr, err := x509.CreateCertificateRequest(rand.Reader, certRequest, privateKey)
	if err != nil {
		return nil, errors.Wrap(err, "create certificate signing request")
	}

	return csr, nil
}

func printCertificate(certificate *x509.Certificate) {
	bytes := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certificate.Raw,
	})
	fmt.Println(string(bytes))
}

func printCsr(csr []byte) {
	csrBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csr,
	})
	fmt.Println(string(csrBytes))
}
