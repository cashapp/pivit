package main

import (
	"encoding/pem"
	"fmt"

	"github.com/pkg/errors"
	"github.com/cashapp/pivit/cmd/pivit/utils"
	"github.com/cashapp/pivit/cmd/pivit/yubikey"
)

// commandPrint exports the certificate.
func commandPrint(slot string) error {
	yk, err := yubikey.Yubikey()
	if err != nil {
		return err
	}

	defer func() {
		_ = yk.Close()
	}()

	cert, err := yk.Certificate(utils.GetSlot(slot))
	if err != nil {
		return errors.Wrap(err, "get PIV certificate")
	}

	certBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})
	fingerprint := utils.CertHexFingerprint(cert)
	_, _ = fmt.Printf("%s\n%s", fingerprint, string(certBytes))

	return nil
}
