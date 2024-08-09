package pivit

import (
	"encoding/pem"

	"github.com/go-piv/piv-go/piv"

	"github.com/pkg/errors"
)

type CertificateOpts struct {
	// Slot to get certificate from
	Slot piv.Slot
}

type CertificateOutput struct {
	Fingerprint    string
	CertificatePem string
}

// Certificate exports the certificate.
func Certificate(yk Pivit, opts *CertificateOpts) (*CertificateOutput, error) {
	cert, err := yk.Certificate(opts.Slot)
	if err != nil {
		return nil, errors.Wrap(err, "get PIV certificate")
	}

	certBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})
	fingerprint := CertHexFingerprint(cert)
	return &CertificateOutput{
		Fingerprint:    fingerprint,
		CertificatePem: string(certBytes),
	}, nil
}
