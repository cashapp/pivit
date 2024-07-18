package utils

import (
	"crypto"
	"crypto/rand"
	"fmt"
	"strings"

	"github.com/pkg/errors"

	"github.com/go-piv/piv-go/piv"
	"github.com/manifoldco/promptui"
)

// GetPin returns the Yubikey PIN entered in stdin
func GetPin() (string, error) {
	validatePin := func(input string) error {
		if len(input) < 6 || len(input) > 8 {
			return fmt.Errorf("PIN must be 6-8 digits long")
		}
		return nil
	}

	prompt := promptui.Prompt{
		Label:    "PIN",
		Validate: validatePin,
		Mask:     '*',
	}

	newPin, err := prompt.Run()
	if err != nil {
		return "", err
	}
	return newPin, nil
}

func Confirm(label string) (bool, error) {
	prompt := promptui.Prompt{
		Label:     label,
		IsConfirm: true,
	}
	result, err := prompt.Run()

	return strings.ToLower(result) == "y", err
}

// GetSlot returns a piv.Slot slot. Defaults to 9e
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

// DeriveManagementKey returns the first 24 bytes of the SHA256 checksum of the given pin
func DeriveManagementKey(pin string) *[24]byte {
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
func GetOrSetManagementKey(yk *piv.YubiKey, pin string) (*[24]byte, error) {
	var newManagementKey *[24]byte
	metadata, err := yk.Metadata(pin)
	if err != nil {
		return nil, err
	}
	if metadata.ManagementKey == nil {
		oldManagementKey := DeriveManagementKey(pin)
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
