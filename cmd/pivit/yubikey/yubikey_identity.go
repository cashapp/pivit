package yubikey

import (
	"crypto"
	"fmt"
	"io"

	"github.com/go-piv/piv-go/piv"
	"github.com/cashapp/pivit/cmd/pivit/utils"
	"github.com/pkg/errors"
)

// Yubikey returns a YubikeySigner with certificate set in its card authentication slots.
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

// YubikeySigner is a type that implements crypto.Signer using a yubikey
type YubikeySigner struct {
	yk *piv.YubiKey
	s piv.Slot
}

var _ crypto.Signer = (*YubikeySigner)(nil)

// NewYubikeySigner returns a YubikeySigner
func NewYubikeySigner(yk *piv.YubiKey, s piv.Slot) YubikeySigner {
	return YubikeySigner{yk: yk, s: s}
}

// Sign implements crypto.Signer
func (y YubikeySigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {


	auth := piv.KeyAuth{
		PINPolicy: piv.PINPolicyAlways,
		PINPrompt: func() (string, error) {
		        pin, err := utils.GetPin()
			if err != nil {
				return "", errors.Wrap(err, "get pin")
			}
			fmt.Println("Touch Yubikey now to sign data...")
			return pin, nil
		},
	}
	if y.s == piv.SlotCardAuthentication {
		auth = piv.KeyAuth{
			PINPolicy: piv.PINPolicyNever,
		}
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
func (y YubikeySigner) Public() crypto.PublicKey {

	cert, err := y.yk.Certificate(y.s)
	if err != nil {
		return nil
	}

	return cert.PublicKey
}
