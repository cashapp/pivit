package pivit

import (
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"

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
			input:           &promptReader{pin: "n\n"},
			expectNilResult: true,
		},
		{
			description:       "self-signed succeeds with assume yes",
			selfSign:          true,
			assumeYes:         true,
			slot:              piv.SlotCardAuthentication,
			shouldGenerateKey: true,
		},
		{
			description:       "self-signed succeeds with confirmation prompt",
			selfSign:          true,
			slot:              piv.SlotCardAuthentication,
			input:             &promptReader{pin: "y\n"},
			shouldGenerateKey: true,
		},
		{
			description:       "generates certificate signing request",
			generateCsr:       true,
			slot:              piv.SlotCardAuthentication,
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
				Algorithm:   piv.AlgorithmEC384,
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

func TestGenerateCertificate_BackwardsCompatibility(t *testing.T) {
	yk, err := testYubikey()
	if err != nil {
		t.Fatal(err)
	}

	patchPivVerify(yk)
	defer unpatchPinVerify()
	defer func() {
		_ = yk.Reset()
	}()

	// Test that when ValidityDays is 0 (default), we get the original behavior
	// with zero times for NotBefore and NotAfter
	opts := &GenerateCertificateOpts{
		Algorithm:    piv.AlgorithmEC384,
		SelfSign:     true,
		AssumeYes:    true,
		ValidityDays: 0, // Default value - should preserve original behavior
		Slot:         piv.SlotCardAuthentication,
		Pin:          piv.DefaultPIN,
	}

	result, err := GenerateCertificate(yk, opts)
	assert.NoError(t, err)
	assert.NotNil(t, result)

	// Parse the certificate and verify it has zero times (backwards compatible behavior)
	block, _ := pem.Decode(result.Certificate)
	cert, err := x509.ParseCertificate(block.Bytes)
	assert.NoError(t, err)
	assert.True(t, cert.NotBefore.IsZero(), "NotBefore should be zero time for backwards compatibility")
	assert.True(t, cert.NotAfter.IsZero(), "NotAfter should be zero time for backwards compatibility")
}

func TestGenerateCertificate_ValidityDays(t *testing.T) {
	yk, err := testYubikey()
	if err != nil {
		t.Fatal(err)
	}

	patchPivVerify(yk)
	defer unpatchPinVerify()
	defer func() {
		_ = yk.Reset()
	}()

	// Test that when ValidityDays > 0, we get proper validity times
	validityDays := 365
	opts := &GenerateCertificateOpts{
		Algorithm:    piv.AlgorithmEC384,
		SelfSign:     true,
		AssumeYes:    true,
		ValidityDays: validityDays,
		Slot:         piv.SlotCardAuthentication,
		Pin:          piv.DefaultPIN,
	}

	before := time.Now()
	result, err := GenerateCertificate(yk, opts)
	after := time.Now()

	assert.NoError(t, err)
	assert.NotNil(t, result)

	// Parse the certificate and verify it has proper validity times
	block, _ := pem.Decode(result.Certificate)
	cert, err := x509.ParseCertificate(block.Bytes)
	assert.NoError(t, err)

	// Verify NotBefore is set to roughly now (with 5 minute negative skew)
	assert.False(t, cert.NotBefore.IsZero(), "NotBefore should not be zero when ValidityDays > 0")
	assert.True(t, cert.NotBefore.Before(before), "NotBefore should be before test start (due to negative skew)")
	assert.True(t, cert.NotBefore.After(before.Add(-10*time.Minute)), "NotBefore should be within 10 minutes of test start")

	// Verify NotAfter is set to roughly ValidityDays from now
	assert.False(t, cert.NotAfter.IsZero(), "NotAfter should not be zero when ValidityDays > 0")
	expectedNotAfter := cert.NotBefore.AddDate(0, 0, validityDays)
	assert.True(t, cert.NotAfter.Equal(expectedNotAfter), "NotAfter should be exactly ValidityDays after NotBefore")
	assert.True(t, cert.NotAfter.After(after.AddDate(0, 0, validityDays-1)), "NotAfter should be roughly ValidityDays from now")
}
