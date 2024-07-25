package pivit

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"io"
	"os"
	"strings"

	"github.com/go-piv/piv-go/piv"

	cms "github.com/github/smimesign/ietf-cms"
	"github.com/pkg/errors"
)

// SignOpts specifies the parameters required when signing data
type SignOpts struct {
	// StatusFd file descriptor to write the "status protocol" to. For more details see the [status] package
	StatusFd int
	// Detach excludes the content being signed from the signature
	Detach bool
	// Armor encodes the signature in a PEM block
	Armor bool
	// UserId identifies the user of the certificate. Can be either an email address or the certificate's fingerprint
	UserId string
	// TimestampAuthority adds a timestamp to the signature from the given URL. See RFC3161 for more details
	TimestampAuthority string
	// Message to sign
	Message io.Reader
	// Slot containing key for signing
	Slot piv.Slot
}

const signedMessagePemHeader = "SIGNED MESSAGE"

// Sign creates a digital signature from the given data in SignOpts.Message
func Sign(yk SecurityKey, opts *SignOpts) error {
	cert, err := yk.Certificate(opts.Slot)
	if err != nil {
		return errors.Wrap(err, "get identity certificate")
	}

	if err = certificateContainsUserId(cert, opts.UserId); err != nil {
		return errors.Wrap(err, "no suitable certificate found")
	}

	yubikeySigner := NewYubikeySigner(yk, opts.Slot)
	SetupStatus(opts.StatusFd)

	dataBuf := new(bytes.Buffer)
	if _, err = io.Copy(dataBuf, opts.Message); err != nil {
		return errors.Wrap(err, "read message to sign")
	}

	sd, err := cms.NewSignedData(dataBuf.Bytes())
	if err != nil {
		return errors.Wrap(err, "create signed data")
	}

	if err = sd.Sign([]*x509.Certificate{cert}, yubikeySigner); err != nil {
		return errors.Wrap(err, "sign message")
	}
	// Git is looking for "\n[GNUPG:] SIG_CREATED ", meaning we need to print a
	// line before SIG_CREATED. BEGIN_SIGNING seems appropriate. GPG emits this,
	// though GPGSM does not.
	EmitBeginSigning()
	if opts.Detach {
		sd.Detached()
	}

	if len(opts.TimestampAuthority) > 0 {
		if err = sd.AddTimestamps(opts.TimestampAuthority); err != nil {
			return errors.Wrap(err, "add timestamp to signature")
		}
	}

	chain := []*x509.Certificate{cert}
	if err = sd.SetCertificates(chain); err != nil {
		return errors.Wrap(err, "set certificates in signature")
	}

	der, err := sd.ToDER()
	if err != nil {
		return errors.Wrap(err, "serialize signature")
	}

	EmitSigCreated(cert, opts.Detach)
	if opts.Armor {
		err = pem.Encode(os.Stdout, &pem.Block{
			Type:  signedMessagePemHeader,
			Bytes: der,
		})
	} else {
		_, err = os.Stdout.Write(der)
	}
	if err != nil {
		return errors.New("write signature")
	}

	return nil
}

func certificateContainsUserId(cert *x509.Certificate, userId string) error {
	email, err := normalizeEmail(userId)
	if err != nil {
		fingerprint := normalizeFingerprint(userId)
		if !strings.EqualFold(CertHexFingerprint(cert), fingerprint) {
			return errors.Errorf("no certificate found with fingerprint %s", fingerprint)
		}
	} else {
		if !certificateContainsEmail(cert, email) {
			return errors.Errorf("no certificate found with email %s", email)
		}
	}

	return nil
}

// normalizeEmail extracts the email address portion from the user ID string
// or an error if the user ID string doesn't contain a valid email address.
//
// The user ID string is expected to be either:
// - An email address
// - A string containing a name, comment and email address, like "Full Name (comment) <email@example.com>"
// - A hex fingerprint
func normalizeEmail(userId string) (string, error) {
	emailStartIndex := strings.Index(userId, "<")
	if emailStartIndex != -1 {
		emailEndIndex := strings.Index(userId, ">")
		return userId[emailStartIndex:emailEndIndex], nil
	}

	if strings.ContainsRune(userId, '@') {
		return userId, nil
	}

	return "", errors.New("user id doesn't contain email address")
}

func normalizeFingerprint(userId string) string {
	return strings.TrimPrefix(userId, "0x")
}

func certificateContainsEmail(certificate *x509.Certificate, email string) bool {
	for _, sanEmail := range certificate.EmailAddresses {
		if sanEmail == email {
			return true
		}
	}

	return false
}
