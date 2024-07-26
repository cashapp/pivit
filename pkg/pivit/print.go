package pivit

import (
	"encoding/pem"
	"fmt"

	"github.com/go-piv/piv-go/piv"

	"github.com/pkg/errors"
)

type PrintCertificateOpts struct {
	// Slot to get certificate from
	Slot piv.Slot
}

// PrintCertificate exports the certificate.
func PrintCertificate(yk Pivit, opts *PrintCertificateOpts) error {
	cert, err := yk.Certificate(opts.Slot)
	if err != nil {
		return errors.Wrap(err, "get PIV certificate")
	}

	certBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})
	fingerprint := CertHexFingerprint(cert)
	_, _ = fmt.Printf("%s\n%s", fingerprint, string(certBytes))

	return nil
}
