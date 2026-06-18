package pivit

import (
	"testing"

	"github.com/go-piv/piv-go/v2/piv"
	"github.com/stretchr/testify/assert"
)

func TestGenerateCertificate(t *testing.T) {
	yk, err := testYubikey()
	if err != nil {
		t.Fatal(err)
	}

	patchPivVerify(yk)
	defer unpatchPinVerify()

	testCases := []struct {
		description string
		selfSign    bool
		generateCsr bool
		assumeYes   bool
		slot        piv.Slot
		algorithm   piv.Algorithm
		input       *promptReader

		expectError       bool
		expectNilResult   bool
		shouldGenerateKey bool
		shouldGenerateCsr bool
	}{
		{
			description:     "self-signing fails when not confirmed",
			selfSign:        true,
			slot:            piv.Slot{},
			algorithm:       piv.AlgorithmEC384,
			input:           &promptReader{pin: "n\n"},
			expectNilResult: true,
		},
		{
			description:       "self-signed succeeds with assume yes",
			selfSign:          true,
			assumeYes:         true,
			slot:              piv.SlotCardAuthentication,
			algorithm:         piv.AlgorithmEC384,
			shouldGenerateKey: true,
		},
		{
			description:       "self-signed succeeds with confirmation prompt",
			selfSign:          true,
			slot:              piv.SlotCardAuthentication,
			algorithm:         piv.AlgorithmEC384,
			input:             &promptReader{pin: "y\n"},
			shouldGenerateKey: true,
		},
		{
			description:       "generates certificate signing request",
			generateCsr:       true,
			slot:              piv.SlotCardAuthentication,
			algorithm:         piv.AlgorithmEC384,
			shouldGenerateKey: true,
			shouldGenerateCsr: true,
		},
		{
			description:       "generates certificate signing request (RSA)",
			generateCsr:       true,
			slot:              piv.SlotCardAuthentication,
			algorithm:         piv.AlgorithmRSA2048,
			shouldGenerateKey: true,
			shouldGenerateCsr: true,
		},
		{
			description:       "generates certificate signing request (ED25519)",
			generateCsr:       true,
			slot:              piv.SlotCardAuthentication,
			algorithm:         piv.AlgorithmEd25519,
			shouldGenerateKey: true,
			shouldGenerateCsr: true,
		},
		{
			description: "fails when both self-sign and generate csr flags are true",
			selfSign:    true,
			generateCsr: true,
			slot:        piv.SlotCardAuthentication,
			expectError: true,
		},
	}
	for _, test := range testCases {
		t.Run(test.description, func(t *testing.T) {
			defer func() {
				_ = yk.Reset()
			}()
			opts := &GenerateCertificateOpts{
				Algorithm:   test.algorithm,
				SelfSign:    test.selfSign,
				GenerateCsr: test.generateCsr,
				AssumeYes:   test.assumeYes,
				PINPolicy:   piv.PINPolicyNever,
				TouchPolicy: piv.TouchPolicyAlways,
				Slot:        piv.SlotCardAuthentication,
				Prompt:      test.input,
				Pin:         piv.DefaultPIN,
			}
			result, err := GenerateCertificate(yk, opts)
			if test.expectError {
				assert.Error(t, err)
				assert.Nil(t, result)
			} else {
				assert.NoError(t, err)
				if test.expectNilResult {
					assert.Nil(t, result)
				} else {
					assert.NotEmpty(t, result.AttestationCertificate)
					if test.shouldGenerateKey {
						assert.NotEmpty(t, result.Certificate)
						assert.NotEmpty(t, yk.slots[test.slot].cert)
					} else {
						assert.Empty(t, result.Certificate)
						assert.Empty(t, yk.slots[test.slot].cert)
					}
					if test.shouldGenerateCsr {
						assert.NotEmpty(t, result.CertificateSigningRequest)
					} else {
						assert.Empty(t, result.CertificateSigningRequest)
					}
				}
			}
		})
	}
}
