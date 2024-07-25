package pivit

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"os"

	"github.com/go-piv/piv-go/piv"

	"github.com/certifi/gocertifi"
	cms "github.com/github/smimesign/ietf-cms"
	"github.com/pkg/errors"
)

// VerifyOpts specifies the parameters required when verifying signatures
type VerifyOpts struct {
	// Signature to verify
	Signature io.Reader
	// Message associated with the signature.
	// This option is only used when verifying a detached signature
	Message io.Reader
	// Slot containing certificate to verify with
	Slot piv.Slot
}

// VerifySignature verifies digital signatures.
// If the given signature is detached, then read the message associated with the signature form VerifyOpts.Message
func VerifySignature(yk SecurityKey, opts *VerifyOpts) error {
	EmitNewSign()

	buf := new(bytes.Buffer)
	if _, err := io.Copy(buf, opts.Signature); err != nil {
		return errors.Wrap(err, "read signature")
	}

	var ber []byte
	if blk, _ := pem.Decode(buf.Bytes()); blk != nil {
		if blk.Type != signedMessagePemHeader {
			return errors.New(fmt.Sprintf("unexpected PEM header: \"%s\"", blk.Type))
		}
		ber = blk.Bytes
	} else {
		ber = buf.Bytes()
	}

	sd, err := cms.ParseSignedData(ber)
	if err != nil {
		return errors.Wrap(err, "parse signature")
	}

	if sd.IsDetached() {
		if opts.Message == nil {
			return errors.New("expected detached signature, but message wasn't provided")
		}
		return verifyDetached(yk, sd, opts.Message, opts.Slot)
	}

	if opts.Message != nil {
		return errors.New("expected to verify attached signature, but still got a message reader")
	}
	return verifyAttached(yk, sd, opts.Slot)
}

func verifyAttached(yk SecurityKey, sd *cms.SignedData, slot piv.Slot) error {
	chains, err := sd.Verify(verifyOpts(yk, slot))
	if err != nil {
		if len(chains) > 0 {
			EmitBadSig(chains)
		} else {
			// TODO: We're omitting a bunch of arguments here.
			EmitErrSig()
		}

		return errors.Wrap(err, "verify signature")
	}

	var (
		cert = chains[0][0][0]
		fpr  = CertHexFingerprint(cert)
		subj = cert.Subject.String()
	)

	_, _ = fmt.Fprintf(os.Stderr, "pivit: Signature made using certificate ID 0x%s\n", fpr)
	EmitGoodSig(chains)

	// TODO: Maybe split up signature checking and certificate checking so we can
	// output something more meaningful.
	_, _ = fmt.Fprintf(os.Stderr, "pivit: Good signature from \"%s\"\n", subj)
	EmitTrustFully()

	return nil
}

func verifyDetached(yk SecurityKey, sd *cms.SignedData, data io.Reader, slot piv.Slot) error {
	buf := new(bytes.Buffer)
	if _, err := io.Copy(buf, data); err != nil {
		return errors.Wrap(err, "read message file")
	}

	chains, err := sd.VerifyDetached(buf.Bytes(), verifyOpts(yk, slot))
	if err != nil {
		if len(chains) > 0 {
			EmitBadSig(chains)
		} else {
			// TODO: We're omitting a bunch of arguments here.
			EmitErrSig()
		}

		return errors.Wrap(err, "failed to verify signature")
	}

	var (
		cert = chains[0][0][0]
		fpr  = CertHexFingerprint(cert)
		subj = cert.Subject.String()
	)

	_, _ = fmt.Fprintf(os.Stderr, "pivit: Signature made using certificate ID 0x%s\n", fpr)
	EmitGoodSig(chains)

	// TODO: Maybe split up signature checking and certificate checking so we can
	// output something more meaningful.
	_, _ = fmt.Fprintf(os.Stderr, "pivit: Good signature from \"%s\"\n", subj)
	EmitTrustFully()

	return nil
}

func verifyOpts(yk SecurityKey, slot piv.Slot) x509.VerifyOptions {
	roots, err := x509.SystemCertPool()
	if err != nil {
		// SystemCertPool isn't implemented for Windows. fall back to mozilla trust store
		roots, err = gocertifi.CACerts()
		if err != nil {
			// fall back to an empty store
			// verification will likely fail
			roots = x509.NewCertPool()
		}
	}

	cert, err := yk.Certificate(slot)
	if err == nil {
		roots.AddCert(cert)
	}

	return x509.VerifyOptions{
		Roots: roots,
		// TODO: we might want to limit signature verification to only certificates that have the right key usage extension
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}
}
