package pivit

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"

	"github.com/go-piv/piv-go/piv"
	"github.com/pkg/errors"
)

// ImportOpts specifies the parameters required when importing a certificate to the yubikey
type ImportOpts struct {
	// CertificateBytes PEM encoded x509 certificate to import to the Yubikey
	CertificateBytes []byte
	// StopAfterFirst if false and CertificateBytes contains more data after the first PEM block, then return an error
	StopAfterFirst bool
	// Slot to store the certificate in
	Slot piv.Slot
	// Pin to access the Yubikey
	Pin string
}

// ImportCertificate stores a certificate file in a yubikey PIV slot
func ImportCertificate(yk Pivit, opts *ImportOpts) error {
	block, rest := pem.Decode(opts.CertificateBytes)
	if (!opts.StopAfterFirst && len(rest) > 0) || block == nil {
		return errors.New("failed to parse certificate")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return errors.Wrap(err, "parse certificate")
	}

	// the presence of a certificate indicates that the slot contains a private key
	// we don't want to import a certificate for a slot that doesn't contain a private key
	existingCertificate, err := yk.Certificate(opts.Slot)
	if err != nil {
		return errors.Wrap(err, "failed to get certificate")
	}
	if existingCertificate == nil {
		return errors.New("certificate not found")
	}

	publicKeyMatches := false
	switch pub := existingCertificate.PublicKey.(type) {
	case *rsa.PublicKey:
		publicKeyMatches = pub.Equal(cert.PublicKey)
	case *ecdsa.PublicKey:
		publicKeyMatches = pub.Equal(cert.PublicKey)
	case *ed25519.PublicKey:
		publicKeyMatches = pub.Equal(cert.PublicKey)
	}
	if !publicKeyMatches {
		return errors.New("imported certificate doesn't match the existing key")
	}

	managementKey, err := GetOrSetManagementKey(yk, opts.Pin)
	if err != nil {
		return errors.Wrap(err, "failed to use management key")
	}

	err = yk.SetCertificate(*managementKey, opts.Slot, cert)
	if err != nil {
		return errors.Wrap(err, "set certificate")
	}

	return nil
}
