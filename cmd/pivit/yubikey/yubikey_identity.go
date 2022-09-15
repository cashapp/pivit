package yubikey

import (
	"crypto"
	"fmt"
	"io"

	"github.com/go-piv/piv-go/piv"
	"github.com/pkg/errors"
)

// Yubikey returns a YubikeySigner with certificate set in its card authentication slots.
func Yubikey() (*piv.YubiKey, error) {
	cards, err := piv.Cards()
	if err != nil {
		return nil, errors.Wrap(err, "enumerate smart cards")
	}

	for _, card := range cards {
		yk, err := piv.Open(card)
		if err != nil {
			continue
		}
		cert, err := yk.Certificate(piv.SlotCardAuthentication)
		if err != nil {
			continue
		}
		if cert != nil {
			return yk, nil
		}
	}
	return nil, errors.New("no yubikey found")
}

// YubikeySigner is a type that implements crypto.Signer using a yubikey
type YubikeySigner struct {
	yk *piv.YubiKey
}

var _ crypto.Signer = (*YubikeySigner)(nil)

// NewYubikeySigner returns a YubikeySigner
func NewYubikeySigner(yk *piv.YubiKey) YubikeySigner {
	return YubikeySigner{yk: yk}
}

// Sign implements crypto.Signer
func (y YubikeySigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	private, err := y.yk.PrivateKey(piv.SlotCardAuthentication, y.Public(), piv.KeyAuth{PINPolicy: piv.PINPolicyNever})
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
func (y YubikeySigner) Public() crypto.PublicKey {
	cert, err := y.yk.Certificate(piv.SlotCardAuthentication)
	if err != nil {
		return nil
	}

	return cert.PublicKey
}
