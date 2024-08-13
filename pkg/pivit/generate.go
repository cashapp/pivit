package pivit

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/url"
	"slices"
	"strconv"

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
	// CertificateParameters
	CertificateParameters CertificateParameters
	// Slot to use for the private key
	Slot piv.Slot
	// Prompt where to get user confirmation from
	Prompt io.ReadCloser
	// Pin to access the Yubikey
	Pin string
}

type CertificateParameters struct {
	SubjectEmailAddress     string
	SubjectOrganization     []string
	SubjectOrganizationUnit []string

	CertificateURIs           []*url.URL
	CertificateIPAddresses    []net.IP
	CertificateEmailAddresses []string
	CertificateDNSNames       []string
}

type GenerateCertificateResults struct {
	// AttestationCertificate PEM encoded X509 certificate that identifies the specific Yubikey device.
	// This certificate is signed by Yubico Inc.'s CA.
	AttestationCertificate []byte
	// Certificate PEM encoded certificate corresponding to the key that was generated.
	// If GenerateCertificateOpts.SelfSign is specified, this certificate is self-signed.
	// Otherwise, it's signed by AttestationCertificate
	Certificate []byte
	// CertificateSigningRequest PEM encoded Certificate Signing Request (CSR) for the generated key.
	CertificateSigningRequest []byte
}

// GenerateCertificate generates a new key pair and a certificate associated with it.
// By default, the certificate is signed by Yubico.
// See the GenerateCertificateOpts.GenerateCsr and GenerateCertificateOpts.SelfSign for other options.
func GenerateCertificate(yk Pivit, opts *GenerateCertificateOpts) (*GenerateCertificateResults, error) {
	if opts.GenerateCsr && opts.SelfSign {
		return nil, errors.New("can't generate a self signed certificate and CSR at the same time")
	}
	if opts.SelfSign && !opts.AssumeYes {
		ok, err := confirm("Are you sure you wish to generate a self-signed certificate?", opts.Prompt)
		if err != nil {
			return nil, err
		}
		if !ok {
			return nil, nil
		}
	}

	// populate the device (attestation) certificate
	result := &GenerateCertificateResults{}
	deviceCert, err := yk.AttestationCertificate()
	if err != nil {
		return nil, errors.Wrap(err, "device cert")
	}
	pemEncodedDeviceCertificate := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: deviceCert.Raw,
	})
	result.AttestationCertificate = pemEncodedDeviceCertificate

	// generate a new key
	managementKey, err := GetOrSetManagementKey(yk, opts.Pin)
	if err != nil {
		return nil, errors.Wrap(err, "failed to use management key")
	}
	key := piv.Key{
		Algorithm:   opts.Algorithm,
		PINPolicy:   opts.PINPolicy,
		TouchPolicy: opts.TouchPolicy,
	}
	publicKey, err := yk.GenerateKey(*managementKey, opts.Slot, key)
	if err != nil {
		return nil, errors.Wrap(err, "generate new key")
	}

	// generate a certificate for the created key (and attest it)
	keyCert, err := yk.Attest(opts.Slot)
	if err != nil {
		return nil, errors.Wrap(err, "attest key")
	}
	err = yk.SetCertificate(*managementKey, opts.Slot, keyCert)
	if err != nil {
		return nil, errors.Wrap(err, "set yubikey certificate")
	}
	auth := piv.KeyAuth{
		PIN: opts.Pin,
	}
	privateKey, err := yk.PrivateKey(opts.Slot, publicKey, auth)
	if err != nil {
		return nil, errors.Wrap(err, "access private key")
	}
	attestation, err := verify(deviceCert, keyCert)
	if err != nil {
		return nil, errors.Wrap(err, "verify device certificate")
	}
	deviceSerialNumber := strconv.FormatUint(uint64(attestation.Serial), 10)
	result.Certificate = pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: keyCert.Raw,
	})

	if opts.SelfSign {
		certificate, err := selfCertificate(deviceSerialNumber, publicKey, privateKey, opts.CertificateParameters)
		if err != nil {
			return nil, err
		}

		if err != nil {
			return nil, errors.Wrap(err, "parse self-signed certificate")
		}

		err = yk.SetCertificate(*managementKey, opts.Slot, certificate)
		if err != nil {
			return nil, errors.Wrap(err, "set certificate")
		}

		result.Certificate = pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: certificate.Raw,
		})
	} else if opts.GenerateCsr {
		certRequest, err := certificateRequest(deviceSerialNumber, privateKey, opts.CertificateParameters)
		if err != nil {
			return nil, err
		}
		result.CertificateSigningRequest = pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE REQUEST",
			Bytes: certRequest,
		})
	}

	return result, nil
}

func randomSerial() (*big.Int, error) {
	maxSerial := new(big.Int)
	// at most 20 bytes (160 bits) long
	maxSerial.Exp(big.NewInt(2), big.NewInt(160), nil).Sub(maxSerial, big.NewInt(1))
	n, err := rand.Int(rand.Reader, maxSerial)
	return n, err
}

func selfCertificate(serialNumber string, publicKey crypto.PublicKey, privateKey crypto.PrivateKey, params CertificateParameters) (*x509.Certificate, error) {
	subject := pkix.Name{
		Organization:       params.SubjectOrganization,
		OrganizationalUnit: params.SubjectOrganizationUnit,
		SerialNumber:       serialNumber,
		CommonName:         params.SubjectEmailAddress,
	}
	extKeyUsage := []x509.ExtKeyUsage{
		x509.ExtKeyUsageClientAuth,
		x509.ExtKeyUsageCodeSigning,
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, errors.Wrap(err, "create certificate random serial")
	}

	if !slices.Contains(params.CertificateEmailAddresses, params.SubjectEmailAddress) {
		params.CertificateEmailAddresses = append(params.CertificateEmailAddresses, params.SubjectEmailAddress)
	}

	cert := &x509.Certificate{
		Subject:         subject,
		SerialNumber:    serial,
		DNSNames:        params.CertificateDNSNames,
		EmailAddresses:  params.CertificateEmailAddresses,
		IPAddresses:     params.CertificateIPAddresses,
		URIs:            params.CertificateURIs,
		KeyUsage:        x509.KeyUsageDigitalSignature,
		ExtKeyUsage:     extKeyUsage,
		ExtraExtensions: []pkix.Extension{},
	}

	data, err := x509.CreateCertificate(rand.Reader, cert, cert, publicKey, privateKey)
	if err != nil {
		return nil, errors.Wrap(err, "create certificate")
	}

	return x509.ParseCertificate(data)
}

func certificateRequest(serialNumber string, privateKey crypto.PrivateKey, params CertificateParameters) ([]byte, error) {
	if !slices.Contains(params.CertificateEmailAddresses, params.SubjectEmailAddress) {
		params.CertificateEmailAddresses = append(params.CertificateEmailAddresses, params.SubjectEmailAddress)
	}
	subject := pkix.Name{
		Organization:       params.SubjectOrganization,
		OrganizationalUnit: params.SubjectOrganizationUnit,
		SerialNumber:       serialNumber,
		CommonName:         params.SubjectEmailAddress,
	}
	certRequest := &x509.CertificateRequest{
		SignatureAlgorithm: x509.ECDSAWithSHA256,
		Subject:            subject,
		DNSNames:           params.CertificateDNSNames,
		EmailAddresses:     params.CertificateEmailAddresses,
		IPAddresses:        params.CertificateIPAddresses,
		URIs:               params.CertificateURIs,
		ExtraExtensions:    []pkix.Extension{},
	}

	csr, err := x509.CreateCertificateRequest(rand.Reader, certRequest, privateKey)
	if err != nil {
		return nil, errors.Wrap(err, "create certificate signing request")
	}

	return csr, nil
}
