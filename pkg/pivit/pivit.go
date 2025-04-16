package pivit

import (
	"crypto"
	"crypto/x509"
	"fmt"
	"io"
	"strconv"

	"github.com/go-piv/piv-go/v2/piv"
	"github.com/pkg/errors"
)

type Pivit interface {
	Close() error
	AttestationCertificate() (*x509.Certificate, error)
	Attest(slot piv.Slot) (*x509.Certificate, error)
	PrivateKey(slot piv.Slot, publicKey crypto.PublicKey, auth piv.KeyAuth) (crypto.PrivateKey, error)
	Certificate(slot piv.Slot) (*x509.Certificate, error)
	SetManagementKey(oldKey, newKey []byte) error
	Metadata(pin string) (*piv.Metadata, error)
	SetMetadata(managementKey []byte, metadata *piv.Metadata) error
	Reset() error
	SetPIN(oldPIN, newPIN string) error
	SetPUK(oldPUK, newPUK string) error
	SetCertificate(managementKey []byte, slot piv.Slot, certificate *x509.Certificate) error
	GenerateKey(managementKey []byte, slot piv.Slot, key piv.Key) (crypto.PublicKey, error)
	Version() piv.Version
}

var _ Pivit = (*piv.YubiKey)(nil)


// YubikeyHandle returns a handle to the connected piv.YubiKey.
// It errors unless there is exactly one YubiKey connected.
func YubikeyHandle() (*piv.YubiKey, error) {
	return YubikeyHandleWithSerial("")
}

// YubikeyHandleWithSerial returns a handle to a piv.YubiKey.
// If serial is empty, returns the YubiKey found only if exactly one card is present.
// If serial is provided, returns the YubiKey with the matching serial number.
func YubikeyHandleWithSerial(serial string) (*piv.YubiKey, error) {
	cards, err := piv.Cards()
	if err != nil {
		return nil, errors.Wrap(err, "enumerate smart cards")
	}

	if len(cards) == 0 {
		return nil, errors.New("no smart card found")
	}

	// If no serial specified, only succeed if exactly one card is present
	if serial == "" {
		if len(cards) > 1 {
			return nil, errors.New("multiple smart cards found but no serial specified")
		}
		yk, err := piv.Open(cards[0])
		return yk, err
	}

	// Parse the expected serial number
	expectedSerial, err := strconv.ParseUint(serial, 10, 32)
	if err != nil {
		return nil, fmt.Errorf("invalid serial number format: %v", err)
	}

	// Serial specified - try to find matching card
	for _, card := range cards {
		yk, err := piv.Open(card)
		if err != nil {
			continue
		}

		// Get serial number
		cardSerial, err := yk.Serial()
		if err != nil {
			yk.Close()
			continue
		}

		if uint64(cardSerial) == expectedSerial {
			return yk, nil
		}
		yk.Close()
	}

	return nil, fmt.Errorf("no smart card found with serial number %s", serial)
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
