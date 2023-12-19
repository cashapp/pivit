package yubikey

import (
	"crypto"
	"fmt"
	"io"

	"github.com/cashapp/pivit/cmd/pivit/utils"
	"github.com/go-piv/piv-go/piv"
	"github.com/pkg/errors"
)

// Yubikey returns a handle to the first Yubikey found in the system
func Yubikey() (*piv.YubiKey, error) {
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

// GetSigner returns a piv.YubiKey for the given slot or an error if the given slot doesn't contain a certificate
func GetSigner(slot string) (*piv.YubiKey, error) {
	cards, err := piv.Cards()
	if err != nil {
		return nil, errors.Wrap(err, "enumerate smart cards")
	}

	for cardName := range cards {
		yk, err := piv.Open(cards[cardName])
		if err != nil {
			continue
		}

		certificate, err := yk.Certificate(utils.GetSlot(slot))
		if err != nil {
			continue
		}

		if certificate != nil {
			return yk, nil
		}
	}

	return nil, errors.New(fmt.Sprintf("no smart card found with certificate in slot %s", slot))
}

// Signer is a type that implements crypto.Signer using a yubikey
type Signer struct {
	yk *piv.YubiKey
	s  piv.Slot
}

var _ crypto.Signer = (*Signer)(nil)

// NewYubikeySigner returns a Signer
func NewYubikeySigner(yk *piv.YubiKey, s piv.Slot) Signer {
	return Signer{yk: yk, s: s}
}

// Sign implements crypto.Signer
func (y Signer) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
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

	auth := piv.KeyAuth{
		PINPrompt: func() (string, error) {
			pin, err := utils.GetPin()
			if err != nil {
				return "", errors.Wrap(err, "get pin")
			}
			return pin, nil
		},
	}

	// yubikeys with version 4.3.0 and lower must have the PINPolicy parameter specified
	// for newer versions, it's automatically inferred from the attestation certificate
	version := y.yk.Version()
	if version.Major < 4 {
		auth.PINPolicy = attestation.PINPolicy
	} else if version.Major == 4 && version.Minor < 3 {
		auth.PINPolicy = attestation.PINPolicy
	}

	private, err := y.yk.PrivateKey(y.s, y.Public(), auth)
	if err != nil {
		return nil, err
	}

	switch private.(type) {
	case *piv.ECDSAPrivateKey:
		return private.(*piv.ECDSAPrivateKey).Sign(rand, digest, opts)
	default:
		return nil, fmt.Errorf("invalid key type")
	}
}

// Public implements crypto.Signer
func (y Signer) Public() crypto.PublicKey {

	cert, err := y.yk.Certificate(y.s)
	if err != nil {
		return nil
	}

	return cert.PublicKey
}
