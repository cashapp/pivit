package pivit

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"

	"github.com/go-piv/piv-go/piv"
	"github.com/pkg/errors"
)

// GenerateCertificateOpts specifies the possible parameters for the key type being generated, and certificate properties
type GenerateCertificateOpts struct {
	// Algorithm elliptic curve algorithm type to use for the key pair
	Algorithm piv.Algorithm
	// SelfSign whether the certificate should be self-signed
	SelfSign bool
	// GenerateCsr whether to generate and print a certificate signing request
	GenerateCsr bool
	// AssumeYes if true, do not prompt the user for anything and assume "yes" for all prompts - useful for scripting
	AssumeYes bool
	// PINPolicy specifies when to prompt for a PIN when accessing the private key.
	// See piv.PINPolicy for more details and possible options
	PINPolicy piv.PINPolicy
	// TouchPolicy specifies when (or if) to touch the yubikey to access the private key
	TouchPolicy piv.TouchPolicy
	// Slot to use for the private key
	Slot piv.Slot
}

// GenerateCertificate generates a new key pair and a certificate associated with it.
// By default, the certificate is signed by Yubico.
// See the GenerateCertificateOpts.GenerateCsr and GenerateCertificateOpts.SelfSign for other options.
func GenerateCertificate(yk Pivit, opts *GenerateCertificateOpts) error {
	if opts.SelfSign && !opts.AssumeYes {
		ok, err := confirm("Are you sure you wish to generate a self-signed certificate?")
		if err != nil {
			return err
		}
		if !ok {
			return nil
		}
	}

	pin, err := GetPin()
	if err != nil {
		return errors.Wrap(err, "get pin")
	}

	managementKey, err := GetOrSetManagementKey(yk, pin)
	if err != nil {
		return errors.Wrap(err, "failed to use management key")
	}

	key := piv.Key{
		Algorithm:   opts.Algorithm,
		PINPolicy:   opts.PINPolicy,
		TouchPolicy: opts.TouchPolicy,
	}

	publicKey, err := yk.GenerateKey(*managementKey, opts.Slot, key)
	if err != nil {
		return errors.Wrap(err, "generate new key")
	}

	deviceCert, err := yk.AttestationCertificate()
	if err != nil {
		return errors.Wrap(err, "device cert")
	}
	fmt.Println("Printing Yubikey device attestation certificate:")
	printCertificate(deviceCert)

	keyCert, err := yk.Attest(opts.Slot)
	if err != nil {
		return errors.Wrap(err, "attest key")
	}
	fmt.Println("Printing generated key certificate:")
	printCertificate(keyCert)
	err = yk.SetCertificate(*managementKey, opts.Slot, keyCert)
	if err != nil {
		return errors.Wrap(err, "set yubikey certificate")
	}

	auth := piv.KeyAuth{
		PIN: pin,
	}
	privateKey, err := yk.PrivateKey(opts.Slot, publicKey, auth)
	if err != nil {
		return errors.Wrap(err, "access private key")
	}
	attestation, err := piv.Verify(deviceCert, keyCert)
	if err != nil {
		return errors.Wrap(err, "verify device certificate")
	}
	if opts.SelfSign {
		if opts.TouchPolicy != piv.TouchPolicyNever {
			fmt.Println("Touch Yubikey now to sign your key...")
		}

		certificate, err := selfCertificate(strconv.FormatUint(uint64(attestation.Serial), 10), publicKey, privateKey)
		if err != nil {
			return err
		}
		fmt.Println("Printing self-signed certificate:")
		printCertificateRaw(certificate)

		cert, err := x509.ParseCertificate(certificate)
		if err != nil {
			return errors.Wrap(err, "parse self-signed certificate")
		}

		if err := importCert(cert, yk, managementKey, opts.Slot); err != nil {
			return errors.Wrap(err, "import self-signed certificate")
		}
	} else if opts.GenerateCsr {
		if opts.TouchPolicy != piv.TouchPolicyNever {
			fmt.Println("Touch Yubikey now to sign your CSR...")
		}

		certRequest, err := certificateRequest(strconv.FormatUint(uint64(attestation.Serial), 10), privateKey)
		if err != nil {
			return err
		}
		fmt.Println("Printing certificate signing request:")
		printCsr(certRequest)
	}

	return nil
}

func randomSerial() (*big.Int, error) {
	maxSerial := new(big.Int)
	// at most 20 bytes (160 bits) long
	maxSerial.Exp(big.NewInt(2), big.NewInt(160), nil).Sub(maxSerial, big.NewInt(1))
	n, err := rand.Int(rand.Reader, maxSerial)
	return n, err
}

func selfCertificate(serialNumber string, publicKey crypto.PublicKey, privateKey crypto.PrivateKey) ([]byte, error) {
	emailAddress := os.Getenv("PIVIT_EMAIL")
	pivitOrg := strings.Split(os.Getenv("PIVIT_ORG"), ",")
	pivitOrgUnit := strings.Split(os.Getenv("PIVIT_ORG_UNIT"), ",")
	subject := pkix.Name{
		Organization:       pivitOrg,
		OrganizationalUnit: pivitOrgUnit,
		SerialNumber:       serialNumber,
		CommonName:         emailAddress,
	}
	extKeyUsage := []x509.ExtKeyUsage{
		x509.ExtKeyUsageClientAuth,
		x509.ExtKeyUsageCodeSigning,
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, errors.Wrap(err, "create certificate random serial")
	}

	cert := &x509.Certificate{
		Subject:         subject,
		SerialNumber:    serial,
		DNSNames:        []string{},
		EmailAddresses:  []string{emailAddress},
		IPAddresses:     []net.IP{},
		URIs:            []*url.URL{},
		KeyUsage:        x509.KeyUsageDigitalSignature,
		ExtKeyUsage:     extKeyUsage,
		ExtraExtensions: []pkix.Extension{},
	}

	data, err := x509.CreateCertificate(rand.Reader, cert, cert, publicKey, privateKey)
	if err != nil {
		return nil, errors.Wrap(err, "create certificate")
	}

	return data, nil
}

func certificateRequest(serialNumber string, privateKey crypto.PrivateKey) ([]byte, error) {
	emailAddress := os.Getenv("PIVIT_EMAIL")
	pivitOrg := strings.Split(os.Getenv("PIVIT_ORG"), ",")
	pivitOrgUnit := strings.Split(os.Getenv("PIVIT_ORG_UNIT"), ",")
	pivitCertUris := strings.Split(os.Getenv("PIVIT_CERT_URIS"), " ")

	certUrls := make([]*url.URL, 0)
	for _, urlString := range pivitCertUris {
		parsed, err := url.Parse(urlString)
		if err == nil {
			certUrls = append(certUrls, parsed)
		}
	}

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
		URIs:               certUrls,
		ExtraExtensions:    []pkix.Extension{},
	}

	csr, err := x509.CreateCertificateRequest(rand.Reader, certRequest, privateKey)
	if err != nil {
		return nil, errors.Wrap(err, "create certificate signing request")
	}

	return csr, nil
}

func printCertificate(certificate *x509.Certificate) {
	printCertificateRaw(certificate.Raw)
}
func printCertificateRaw(cert []byte) {
	bytes := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert,
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
