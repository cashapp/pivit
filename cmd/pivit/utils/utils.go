package utils

import (
	"crypto/sha1"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"

	"github.com/go-piv/piv-go/piv"
	"github.com/manifoldco/promptui"
)

// CertHexFingerprint returns the SHA1 checksum a certificate's raw bytes
func CertHexFingerprint(certificate *x509.Certificate) string {
	fpr := sha1.Sum(certificate.Raw)
	fingerprintString := hex.EncodeToString(fpr[:])
	return fingerprintString

}

// GetPin returns the Yubikey PIN entered in stdin
func GetPin() (string, error) {
	validatePin := func(input string) error {
		if len(input) < 6 || len(input) > 8 {
			return fmt.Errorf("PIN must be 6-8 digits long")
		}
		if _, err := strconv.Atoi(input); err != nil {
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

	return (strings.ToLower(result) == "y"), err
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
