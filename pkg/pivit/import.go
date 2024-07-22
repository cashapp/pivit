package pivit

import (
	"crypto/x509"
	"encoding/pem"
	"os"

	"github.com/cashapp/pivit/pkg/pivit/utils"
	"github.com/cashapp/pivit/pkg/pivit/yubikey"
	"github.com/go-piv/piv-go/piv"
	"github.com/pkg/errors"
)

type ImportOpts struct {
	Filename       string
	StopAfterFirst bool
}

// ImportCertificate stores a certificate file in a yubikey PIV slot
func ImportCertificate(slot string, opts *ImportOpts) error {
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

	yk, err := yubikey.GetSigner(slot)
	if err != nil {
		return errors.Wrap(err, "enumerate smart cards")
	}
	defer func() {
		_ = yk.Close()
	}()

	pin, err := utils.GetPin()
	if err != nil {
		return errors.Wrap(err, "get pin")
	}

	managementKey, err := utils.GetOrSetManagementKey(yk, pin)
	if err != nil {
		return errors.Wrap(err, "failed to use management key")
	}
	return importCert(cert, yk, managementKey, slot)
}

func importCert(cert *x509.Certificate, yk *piv.YubiKey, managementKey *[24]byte, slot string) error {
	err := yk.SetCertificate(*managementKey, utils.GetSlot(slot), cert)
	if err != nil {
		return errors.Wrap(err, "set certificate")
	}

	return nil
}
