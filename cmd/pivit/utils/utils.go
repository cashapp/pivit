package utils

import (
	"crypto/sha1"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"strconv"

	"github.com/manifoldco/promptui"
	"github.com/go-piv/piv-go/piv"
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

// Returns PIV slot. Slot 9e by default
func GetSlot(slot string) piv.Slot {
	var slotMap = map[string]piv.Slot{
		piv.SlotCardAuthentication.String(): piv.SlotCardAuthentication,
		piv.SlotAuthentication.String():	 piv.SlotAuthentication,
		piv.SlotSignature.String():			 piv.SlotSignature,
		piv.SlotKeyManagement.String():		 piv.SlotKeyManagement,
	}

	pivSlot := slotMap[slot]

	return pivSlot
}
