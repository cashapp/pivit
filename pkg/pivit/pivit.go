package pivit

import (
	"crypto"
	"crypto/x509"
	"fmt"
	"io"

	"github.com/go-piv/piv-go/piv"
	"github.com/pkg/errors"
)

type Pivit interface {
	Close() error
	AttestationCertificate() (*x509.Certificate, error)
	Attest(slot piv.Slot) (*x509.Certificate, error)
	PrivateKey(slot piv.Slot, publicKey crypto.PublicKey, auth piv.KeyAuth) (crypto.PrivateKey, error)
	Certificate(slot piv.Slot) (*x509.Certificate, error)
	SetManagementKey(oldKey, newKey [24]byte) error
	Metadata(pin string) (*piv.Metadata, error)
	SetMetadata(managementKey [24]byte, metadata *piv.Metadata) error
	Reset() error
	SetPIN(oldPIN, newPIN string) error
	SetPUK(oldPUK, newPUK string) error
	SetCertificate(managementKey [24]byte, slot piv.Slot, certificate *x509.Certificate) error
	GenerateKey(managementKey [24]byte, slot piv.Slot, key piv.Key) (crypto.PublicKey, error)
	Version() piv.Version
}

var _ Pivit = (*piv.YubiKey)(nil)

// YubikeyHandle returns a handle to the first piv.YubiKey found in the system
func YubikeyHandle() (*piv.YubiKey, error) {
	cards, err := piv.Cards()
	if err != nil {
		return nil, errors.Wrap(err, "enumerate smart cards")
	}

	if len(cards) != 1 {
		return nil, errors.New("no smart card found")
	}

	yk, err := piv.Open(cards[0])
	return yk, err
}

// signer implements crypto.Signer using a yubikey
type signer struct {
	yk    Pivit
	s     piv.Slot
	stdin io.Reader
}

var _ crypto.Signer = (*signer)(nil)

// NewYubikeySigner returns a signer
func NewYubikeySigner(yk Pivit, s piv.Slot, stdin io.Reader) crypto.Signer {
	return signer{
		yk:    yk,
		s:     s,
		stdin: stdin,
	}
}

// Sign implements crypto.Signer
func (y signer) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	auth := piv.KeyAuth{
		PINPrompt: func() (string, error) {
			pin, err := GetPin(y.stdin)
			if err != nil {
				return "", errors.Wrap(err, "get pin")
			}
			return pin, nil
		},
	}

	// yubikeys with version 4.3.0 and lower must have the PINPolicy parameter specified
	// for newer versions, it's automatically inferred from the attestation certificate
	version := y.yk.Version()
	if version.Major < 4 || (version.Major == 4 && version.Minor < 3) {
		pinPolicy, err := y.getPINPolicy()
		if err != nil {
			return nil, err
		}

		auth.PINPolicy = *pinPolicy
	}

	private, err := y.yk.PrivateKey(y.s, y.Public(), auth)
	if err != nil {
		return nil, err
	}

	switch priv := private.(type) {
	case crypto.Signer:
		return priv.Sign(rand, digest, opts)
	default:
		return nil, fmt.Errorf("invalid key type")
	}
}

// Public implements crypto.Signer
func (y signer) Public() crypto.PublicKey {

	cert, err := y.yk.Certificate(y.s)
	if err != nil {
		return nil
	}

	return cert.PublicKey
}

func (y signer) getPINPolicy() (*piv.PINPolicy, error) {
	attestationCert, err := y.yk.AttestationCertificate()
	if err != nil {
		return nil, err
	}

	keyCert, err := y.yk.Certificate(y.s)
	if err != nil {
		return nil, err
	}

	attestation, err := piv.Verify(attestationCert, keyCert)
	if err != nil {
		return nil, err
	}
	return &attestation.PINPolicy, nil
}

var verify = piv.Verify
