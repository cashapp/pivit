package pivit

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"os"
	"testing"

	"github.com/go-piv/piv-go/piv"
	"github.com/stretchr/testify/assert"
)

func TestSign(t *testing.T) {
	yk, err := testYubikey()
	if err != nil {
		t.Fatal(err)
	}

	patchPivVerify(yk)
	defer unpatchPinVerify()

	genOpts := &GenerateCertificateOpts{
		Algorithm:   piv.AlgorithmEC384,
		SelfSign:    true,
		GenerateCsr: false,
		AssumeYes:   true,
		PINPolicy:   piv.PINPolicyNever,
		TouchPolicy: piv.TouchPolicyAlways,
		Slot:        piv.SlotCardAuthentication,
		Prompt: &pinReader{
			pin: piv.DefaultPIN + "\n",
		},
	}
	result, err := GenerateCertificate(yk, genOpts)
	if err != nil {
		t.Fatal(err)
	}

	pemCert, _ := pem.Decode(result.Certificate)
	cert, err := x509.ParseCertificate(pemCert.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint := CertHexFingerprint(cert)

	testCases := []struct {
		description  string
		armor        bool
		detach       bool
		userId       string
		timestampUrl string
		slot         piv.Slot
		expectError  bool
		skipCI       bool
	}{
		{
			description: "no certificate found",
			slot:        piv.SlotSignature,
			expectError: true,
		},
		{
			description: "bad fingerprint",
			slot:        piv.SlotCardAuthentication,
			expectError: true,
		},
		{
			description: "default options",
			userId:      fingerprint,
			slot:        piv.SlotCardAuthentication,
		},
		{
			description: "with armor",
			armor:       true,
			userId:      fingerprint,
			slot:        piv.SlotCardAuthentication,
		},
		{
			description: "detached signature",
			detach:      true,
			userId:      fingerprint,
			slot:        piv.SlotCardAuthentication,
		},
		{
			description:  "with timestamp server",
			userId:       fingerprint,
			timestampUrl: "http://timestamp.digicert.com",
			slot:         piv.SlotCardAuthentication,
			skipCI:       true,
		},
		{
			description:  "bad timestamp server",
			userId:       fingerprint,
			timestampUrl: "http://127.0.0.1",
			slot:         piv.SlotCardAuthentication,
			expectError:  true,
		},
	}
	for _, test := range testCases {
		t.Run(test.description, func(t *testing.T) {
			if test.skipCI {
				skipCI(t)
			}

			signOpts := &SignOpts{
				StatusFd:           0,
				Detach:             test.detach,
				Armor:              test.armor,
				UserId:             test.userId,
				TimestampAuthority: test.timestampUrl,
				Message:            &bytes.Buffer{},
				Slot:               test.slot,
				Prompt:             nil,
			}
			sig, err := Sign(yk, signOpts)
			if test.expectError {
				assert.Error(t, err)
				assert.Nil(t, sig)
			} else {
				assert.NoError(t, err)
				assert.NotEmpty(t, sig)
				if test.armor {
					block, _ := pem.Decode(sig)
					assert.Equal(t, "SIGNED MESSAGE", block.Type)
				}
			}
		})
	}
}

// skipCI skips a test if we can determine the environment we're running in is a NixOS sandbox
// it's used to skip tests that use networking for example
func skipCI(t *testing.T) {
	if os.Getenv("NIX_ENFORCE_PURITY") != "" {
		t.Skip("Skipping test in CI environment")
	}
}
