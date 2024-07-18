package main

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"os"

	"github.com/cashapp/pivit/cmd/pivit/status"
	"github.com/cashapp/pivit/cmd/pivit/utils"
	"github.com/cashapp/pivit/cmd/pivit/yubikey"
	pivitutils "github.com/cashapp/pivit/pkg/pivit/utils"
	"github.com/certifi/gocertifi"
	cms "github.com/github/smimesign/ietf-cms"
	"github.com/pkg/errors"
)

// commandVerify verifies the data and signatures supplied in fileArgs
func commandVerify(fileArgs []string, slot string) error {
	status.EmitNewSign()

	if len(fileArgs) < 2 {
		return verifyAttached(fileArgs, slot)
	}

	return verifyDetached(fileArgs, slot)
}

func verifyAttached(fileArgs []string, slot string) error {
	var (
		f   io.ReadCloser
		err error
	)

	// read in signature
	if len(fileArgs) == 1 {
		if f, err = os.Open(fileArgs[0]); err != nil {
			return errors.Wrapf(err, "open signature file (%s)", fileArgs[0])
		}
		defer func() {
			_ = f.Close()
		}()
	} else {
		f = os.Stdin
	}

	buf := new(bytes.Buffer)
	if _, err = io.Copy(buf, f); err != nil {
		return errors.Wrap(err, "read signature")
	}

	// try decoding as PEM
	var ber []byte
	if blk, _ := pem.Decode(buf.Bytes()); blk != nil {
		ber = blk.Bytes
	} else {
		ber = buf.Bytes()
	}

	// parse signature
	sd, err := cms.ParseSignedData(ber)
	if err != nil {
		return errors.Wrap(err, "parse signature")
	}

	// verify signature
	chains, err := sd.Verify(verifyOpts(slot))
	if err != nil {
		if len(chains) > 0 {
			status.EmitBadSig(chains)
		} else {
			// TODO: We're omitting a bunch of arguments here.
			status.EmitErrSig()
		}

		return errors.Wrap(err, "verify signature")
	}

	var (
		cert = chains[0][0][0]
		fpr  = pivitutils.CertHexFingerprint(cert)
		subj = cert.Subject.String()
	)

	_, _ = fmt.Fprintf(os.Stderr, "pivit: Signature made using certificate ID 0x%s\n", fpr)
	status.EmitGoodSig(chains)

	// TODO: Maybe split up signature checking and certificate checking so we can
	// output something more meaningful.
	_, _ = fmt.Fprintf(os.Stderr, "pivit: Good signature from \"%s\"\n", subj)
	status.EmitTrustFully()

	return nil
}

func verifyDetached(fileArgs []string, slot string) error {
	var (
		f   io.ReadCloser
		err error
	)

	// read in signature
	if f, err = os.Open(fileArgs[0]); err != nil {
		return errors.Wrapf(err, "open signature file (%s)", fileArgs[0])
	}
	defer func() {
		_ = f.Close()
	}()

	buf := new(bytes.Buffer)
	if _, err = io.Copy(buf, f); err != nil {
		return errors.Wrap(err, "read signature file")
	}

	// try decoding as PEM
	var ber []byte
	if blk, _ := pem.Decode(buf.Bytes()); blk != nil {
		ber = blk.Bytes
	} else {
		ber = buf.Bytes()
	}

	// parse signature
	sd, err := cms.ParseSignedData(ber)
	if err != nil {
		return errors.Wrap(err, "parse signature")
	}

	// read in signed data
	if fileArgs[1] == "-" {
		f = os.Stdin
	} else {
		if f, err = os.Open(fileArgs[1]); err != nil {
			return errors.Wrapf(err, "open message file (%s)", fileArgs[1])
		}
		defer func() {
			_ = f.Close()
		}()
	}

	// verify signature
	buf.Reset()
	if _, err = io.Copy(buf, f); err != nil {
		return errors.Wrap(err, "read message file")
	}

	chains, err := sd.VerifyDetached(buf.Bytes(), verifyOpts(slot))
	if err != nil {
		if len(chains) > 0 {
			status.EmitBadSig(chains)
		} else {
			// TODO: We're omitting a bunch of arguments here.
			status.EmitErrSig()
		}

		return errors.Wrap(err, "failed to verify signature")
	}

	var (
		cert = chains[0][0][0]
		fpr  = pivitutils.CertHexFingerprint(cert)
		subj = cert.Subject.String()
	)

	_, _ = fmt.Fprintf(os.Stderr, "pivit: Signature made using certificate ID 0x%s\n", fpr)
	status.EmitGoodSig(chains)

	// TODO: Maybe split up signature checking and certificate checking so we can
	// output something more meaningful.
	_, _ = fmt.Fprintf(os.Stderr, "pivit: Good signature from \"%s\"\n", subj)
	status.EmitTrustFully()

	return nil
}

func verifyOpts(slot string) x509.VerifyOptions {
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

	yk, err := yubikey.GetSigner(slot)

	if err == nil {
		cert, err := yk.Certificate(utils.GetSlot(slot))
		if err == nil {
			roots.AddCert(cert)
		}
		_ = yk.Close()
	}

	return x509.VerifyOptions{
		Roots: roots,
		// TODO: we might want to limit signature verification to only certificates that have the right key usage extension
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}
}
