package pivit

import (
	"crypto/x509"
	"encoding/pem"
	"os"

	"github.com/go-piv/piv-go/piv"
	"github.com/pkg/errors"
)

// ImportOpts specifies the parameters required when importing a certificate to the yubikey
type ImportOpts struct {
	// Filename from which to read the certificate data from
	Filename string
	// StopAfterFirst if false and Filename contains more data after the first PEM block, then return an error
	StopAfterFirst bool
	// Slot to store the certificate in
	Slot piv.Slot
}

// ImportCertificate stores a certificate file in a yubikey PIV slot
func ImportCertificate(yk Pivit, opts *ImportOpts) error {
	certBytes, err := os.ReadFile(opts.Filename)
	if err != nil {
		return errors.Wrap(err, "read certificate file")
	}

	block, rest := pem.Decode(certBytes)
	if (!opts.StopAfterFirst && len(rest) > 0) || block == nil {
		return errors.New("failed to parse certificate")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return errors.Wrap(err, "parse certificate")
	}

	// the presence of a certificate indicates that the slot contains a private key
	// we don't want to import a certificate for a slot that doesn't contain a private key
	certificate, err := yk.Certificate(opts.Slot)
	if err != nil {
		return errors.Wrap(err, "failed to get certificate")
	}
	if certificate == nil {
		return errors.New("certificate not found")
	}

	pin, err := GetPin()
	if err != nil {
		return errors.Wrap(err, "get pin")
	}

	managementKey, err := GetOrSetManagementKey(yk, pin)
	if err != nil {
		return errors.Wrap(err, "failed to use management key")
	}
	return importCert(cert, yk, managementKey, opts.Slot)
}

func importCert(cert *x509.Certificate, yk Pivit, managementKey *[24]byte, slot piv.Slot) error {
	err := yk.SetCertificate(*managementKey, slot, cert)
	if err != nil {
		return errors.Wrap(err, "set certificate")
	}

	return nil
}
