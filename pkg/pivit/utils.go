package pivit

import (
	"crypto"
	"crypto/rand"
	"crypto/sha1"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"io"
	"strings"

	"github.com/go-piv/piv-go/piv"
	"github.com/manifoldco/promptui"
	"github.com/pkg/errors"
)

// CertHexFingerprint returns the SHA1 checksum a certificate's raw bytes
func CertHexFingerprint(certificate *x509.Certificate) string {
	fpr := sha1.Sum(certificate.Raw)
	fingerprintString := hex.EncodeToString(fpr[:])
	return fingerprintString
}

// GetPin prompts the user for a PIN
func GetPin(reader io.Reader) (string, error) {
	validatePin := func(input string) error {
		if len(input) < 6 || len(input) > 8 {
			return fmt.Errorf("PIN must be 6-8 digits long")
		}
		return nil
	}

	// promptui.Prompt requires io.ReadCloser for some reason, but it's much nicer to pass io.Reader
	// if what the user gave us doesn't implement io.ReadCloser, we'll wrap it for them
	readCloser, ok := reader.(io.ReadCloser)
	if !ok {
		readCloser = readeCloser(reader)
	}
	prompt := promptui.Prompt{
		Label:    "PIN",
		Validate: validatePin,
		Mask:     '*',
		Stdin:    readCloser,
	}

	newPin, err := prompt.Run()
	if err != nil {
		return "", err
	}
	return newPin, nil
}

func confirm(label string, stdin io.ReadCloser) (bool, error) {
	prompt := promptui.Prompt{
		Label:     label,
		IsConfirm: true,
		Stdin:     stdin,
	}
	result, err := prompt.Run()
	if errors.Is(err, promptui.ErrAbort) {
		return false, nil
	}
	return strings.ToLower(result) == "y", err
}

// GetSlot returns a piv.Slot. Defaults to 9e
func GetSlot(slot string) piv.Slot {
	switch slot {
	case piv.SlotCardAuthentication.String():
		return piv.SlotCardAuthentication
	case piv.SlotAuthentication.String():
		return piv.SlotAuthentication
	case piv.SlotSignature.String():
		return piv.SlotSignature
	case piv.SlotKeyManagement.String():
		return piv.SlotKeyManagement
	default:
		return piv.SlotCardAuthentication
	}
}

// RandomManagementKey returns a *[24]byte slice filled with random byte values
func RandomManagementKey() (*[24]byte, error) {
	mk := make([]byte, 24)
	if _, err := rand.Reader.Read(mk); err != nil {
		return nil, err
	}
	return (*[24]byte)(mk), nil
}

// deriveManagementKey returns the first 24 bytes of the SHA256 checksum of the given pin
// NOTE: this function has an error in it and SHOULD NOT BE USED.
// It'll return the same checksum every time it's being called.
// Its only use case should be in the GetOrSetManagementKey function for legacy reasons.
func deriveManagementKey(pin string) *[24]byte {
	hash := crypto.SHA256.New()
	checksum := hash.Sum([]byte(pin))
	var mk [24]byte
	copy(mk[:], checksum[:24])
	return &mk
}

// GetOrSetManagementKey returns the management key from the PIV metadata section.
// If it's not found, it derives the management key from the PIN, and will then:
//  1. create a new random management key
//  2. set it as the new management key
//  3. store it in the PIV metadata section
//  4. return the newly set management key
func GetOrSetManagementKey(yk Pivit, pin string) (*[24]byte, error) {
	var newManagementKey *[24]byte
	metadata, err := yk.Metadata(pin)
	if err != nil {
		return nil, err
	}
	if metadata.ManagementKey == nil {
		oldManagementKey := deriveManagementKey(pin)
		randomManagementKey, err := RandomManagementKey()
		if err != nil {
			return nil, errors.Wrap(err, "failed to generate random management key")
		}

		if err = yk.SetManagementKey(*oldManagementKey, *randomManagementKey); err != nil {
			return nil, errors.Wrap(err, "set new management key")
		}
		if err = yk.SetMetadata(*randomManagementKey, &piv.Metadata{
			ManagementKey: randomManagementKey,
		}); err != nil {
			return nil, errors.Wrap(err, "failed to store new management key")
		}

		newManagementKey = randomManagementKey
	} else {
		newManagementKey = metadata.ManagementKey
	}
	return newManagementKey, nil
}

func readeCloser(reader io.Reader) io.ReadCloser {
	readCloser, ok := reader.(io.ReadCloser)
	if ok {
		return readCloser
	}
	return ReaderWrapper{reader}
}

type ReaderWrapper struct {
	io.Reader
}

func (r ReaderWrapper) Close() error {
	return nil
}

var _ io.ReadCloser = (*ReaderWrapper)(nil)
