package pivit

import (
	"testing"

	"github.com/go-piv/piv-go/piv"
	"github.com/stretchr/testify/assert"
)

func TestGenerateCertificate_selfSigned_notConfirmed(t *testing.T) {
	yk, err := testYubikey()
	if err != nil {
		t.Fatal(err)
	}

	pin := &pinReader{pin: "n\n" + piv.DefaultPIN + "\n"}
	opts := &GenerateCertificateOpts{
		Algorithm:   piv.AlgorithmEC256,
		SelfSign:    true,
		GenerateCsr: false,
		AssumeYes:   false,
		PINPolicy:   piv.PINPolicyNever,
		TouchPolicy: piv.TouchPolicyAlways,
		Slot:        piv.Slot{},
		Prompt:      pin,
	}
	err = GenerateCertificate(yk, opts)
	assert.NoError(t, err)
	assert.Empty(t, yk.slots)
}

func TestGenerateCertificate_selfSigned_assumeYes(t *testing.T) {
	yk, err := testYubikey()
	if err != nil {
		t.Fatal(err)
	}
	patchPivVerify(yk)
	defer unpatchPinVerify()

	pin := &pinReader{pin: piv.DefaultPIN + "\n"}
	opts := &GenerateCertificateOpts{
		Algorithm:   piv.AlgorithmEC256,
		SelfSign:    true,
		GenerateCsr: false,
		AssumeYes:   true,
		PINPolicy:   piv.PINPolicyNever,
		TouchPolicy: piv.TouchPolicyAlways,
		Slot:        piv.SlotCardAuthentication,
		Prompt:      pin,
	}
	err = GenerateCertificate(yk, opts)
	assert.NoError(t, err)
	assert.NotEmpty(t, yk.slots[piv.SlotCardAuthentication])
}

func TestGenerateCertificate_selfSigned_confirmed(t *testing.T) {
	yk, err := testYubikey()
	if err != nil {
		t.Fatal(err)
	}
	patchPivVerify(yk)
	defer unpatchPinVerify()

	pin := &pinReader{pin: "y\n" + piv.DefaultPIN + "\n"}
	opts := &GenerateCertificateOpts{
		Algorithm:   piv.AlgorithmEC256,
		SelfSign:    true,
		GenerateCsr: false,
		AssumeYes:   false,
		PINPolicy:   piv.PINPolicyNever,
		TouchPolicy: piv.TouchPolicyAlways,
		Slot:        piv.SlotCardAuthentication,
		Prompt:      pin,
	}
	err = GenerateCertificate(yk, opts)
	assert.NoError(t, err)
	assert.NotEmpty(t, yk.slots[piv.SlotCardAuthentication])
}

func TestGenerateCertificate_generateCsr(t *testing.T) {
	yk, err := testYubikey()
	if err != nil {
		t.Fatal(err)
	}
	patchPivVerify(yk)
	defer unpatchPinVerify()

	pin := &pinReader{pin: piv.DefaultPIN + "\n"}
	opts := &GenerateCertificateOpts{
		Algorithm:   piv.AlgorithmEC256,
		SelfSign:    false,
		GenerateCsr: true,
		AssumeYes:   false,
		PINPolicy:   piv.PINPolicyNever,
		TouchPolicy: piv.TouchPolicyAlways,
		Slot:        piv.SlotCardAuthentication,
		Prompt:      pin,
	}
	err = GenerateCertificate(yk, opts)
	assert.NoError(t, err)
	assert.NotEmpty(t, yk.slots[piv.SlotCardAuthentication])
}

func TestGenerateCertificate_badFlags(t *testing.T) {
	opts := &GenerateCertificateOpts{
		Algorithm:   piv.AlgorithmEC256,
		SelfSign:    true,
		GenerateCsr: true,
		AssumeYes:   false,
		PINPolicy:   piv.PINPolicyNever,
		TouchPolicy: piv.TouchPolicyAlways,
		Slot:        piv.SlotCardAuthentication,
		Prompt:      nil,
	}
	err := GenerateCertificate(nil, opts)
	assert.Error(t, err)
}
