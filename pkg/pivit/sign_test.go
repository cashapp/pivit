package pivit

import (
	"bytes"
	"testing"

	"github.com/go-piv/piv-go/piv"
	"github.com/stretchr/testify/assert"
)

func TestSign_noFingerprint(t *testing.T) {
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
	err = GenerateCertificate(yk, genOpts)
	if err != nil {
		t.Fatal(err)
	}

	signOpts := &SignOpts{
		StatusFd:           0,
		Detach:             true,
		Armor:              true,
		UserId:             "NO MATCH",
		TimestampAuthority: "",
		Message:            &bytes.Buffer{},
		Slot:               piv.SlotCardAuthentication,
		Prompt:             nil,
	}
	err = Sign(yk, signOpts)
	assert.Error(t, err)
}

func TestSign_happyPath(t *testing.T) {
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
	err = GenerateCertificate(yk, genOpts)
	if err != nil {
		t.Fatal(err)
	}

	cert := yk.slots[piv.SlotCardAuthentication].cert
	fingerprint := CertHexFingerprint(cert)
	signOpts := &SignOpts{
		StatusFd:           0,
		Detach:             true,
		Armor:              true,
		UserId:             fingerprint,
		TimestampAuthority: "http://timestamp.digicert.com",
		Message:            &bytes.Buffer{},
		Slot:               piv.SlotCardAuthentication,
		Prompt:             nil,
	}
	err = Sign(yk, signOpts)
	assert.NoError(t, err)
}

func TestSign_emptySlot(t *testing.T) {
	yk, err := testYubikey()
	if err != nil {
		t.Fatal(err)
	}

	patchPivVerify(yk)
	defer unpatchPinVerify()

	signOpts := &SignOpts{
		StatusFd:           0,
		Detach:             true,
		Armor:              true,
		UserId:             "",
		TimestampAuthority: "",
		Message:            &bytes.Buffer{},
		Slot:               piv.SlotCardAuthentication,
		Prompt:             nil,
	}
	err = Sign(yk, signOpts)
	assert.Error(t, err)
}

func TestSign_badTimestampServer(t *testing.T) {
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
	err = GenerateCertificate(yk, genOpts)
	if err != nil {
		t.Fatal(err)
	}

	cert := yk.slots[piv.SlotCardAuthentication].cert
	fingerprint := CertHexFingerprint(cert)
	signOpts := &SignOpts{
		StatusFd:           0,
		Detach:             true,
		Armor:              true,
		UserId:             fingerprint,
		TimestampAuthority: "http://127.0.0.1",
		Message:            &bytes.Buffer{},
		Slot:               piv.SlotCardAuthentication,
		Prompt:             nil,
	}
	err = Sign(yk, signOpts)
	assert.Error(t, err)
}

func TestSign_attached(t *testing.T) {
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
	err = GenerateCertificate(yk, genOpts)
	if err != nil {
		t.Fatal(err)
	}

	cert := yk.slots[piv.SlotCardAuthentication].cert
	fingerprint := CertHexFingerprint(cert)
	signOpts := &SignOpts{
		StatusFd:           0,
		Detach:             false,
		Armor:              true,
		UserId:             fingerprint,
		TimestampAuthority: "",
		Message:            &bytes.Buffer{},
		Slot:               piv.SlotCardAuthentication,
		Prompt:             nil,
	}
	err = Sign(yk, signOpts)
	assert.NoError(t, err)
}

func TestSign_unarmored(t *testing.T) {
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
	err = GenerateCertificate(yk, genOpts)
	if err != nil {
		t.Fatal(err)
	}

	cert := yk.slots[piv.SlotCardAuthentication].cert
	fingerprint := CertHexFingerprint(cert)
	signOpts := &SignOpts{
		StatusFd:           0,
		Detach:             true,
		Armor:              false,
		UserId:             fingerprint,
		TimestampAuthority: "",
		Message:            &bytes.Buffer{},
		Slot:               piv.SlotCardAuthentication,
		Prompt:             nil,
	}
	err = Sign(yk, signOpts)
	assert.NoError(t, err)
}
