package pivit

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"io"
	"testing"

	"github.com/go-piv/piv-go/v2/piv"
	"github.com/stretchr/testify/assert"
)

func TestVerifySignature(t *testing.T) {
	yk, err := testYubikey()
	if err != nil {
		t.Fatal(err)
	}
	patchPivVerify(yk)
	defer unpatchPinVerify()

	result, err := GenerateCertificate(yk, &GenerateCertificateOpts{
		Algorithm:   piv.AlgorithmEC384,
		SelfSign:    false,
		GenerateCsr: false,
		AssumeYes:   true,
		PINPolicy:   piv.PINPolicyNever,
		TouchPolicy: piv.TouchPolicyAlways,
		Slot:        piv.SlotCardAuthentication,
		Pin:         piv.DefaultPIN,
	})
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
		name    string
		detach  bool
		armor   bool
		message io.Reader
	}{
		{
			name:    "detached, not armored",
			detach:  true,
			armor:   false,
			message: &bytes.Buffer{},
		},
		{
			name:    "attached, not armored",
			detach:  false,
			armor:   false,
			message: &bytes.Buffer{},
		},
		{
			name:    "detached and armored",
			detach:  true,
			armor:   true,
			message: &bytes.Buffer{},
		},
		{
			name:    "attached and armored",
			detach:  false,
			armor:   true,
			message: &bytes.Buffer{},
		},
	}

	for _, test := range testCases {
		t.Run(test.name, func(t *testing.T) {
			sig, err := Sign(yk, &SignOpts{
				StatusFd:           0,
				Detach:             test.detach,
				Armor:              test.armor,
				UserId:             fingerprint,
				TimestampAuthority: "",
				Message:            test.message,
				Slot:               piv.SlotCardAuthentication,
			})
			if err != nil {
				t.Fatal(err)
			}

			var message io.Reader
			if test.detach {
				message = test.message
			} else {
				message = nil
			}
			err = VerifySignature(yk, &VerifyOpts{
				Signature: bytes.NewReader(sig),
				Message:   message,
				Slot:      piv.SlotCardAuthentication,
			})
			assert.NoError(t, err)
		})
	}

	t.Run("attached with message parameter", func(t *testing.T) {
		sig, err := Sign(yk, &SignOpts{
			StatusFd:           0,
			Detach:             false,
			Armor:              false,
			UserId:             fingerprint,
			TimestampAuthority: "",
			Message:            &bytes.Buffer{},
			Slot:               piv.SlotCardAuthentication,
		})
		if err != nil {
			t.Fatal(err)
		}
		err = VerifySignature(yk, &VerifyOpts{
			Signature: bytes.NewReader(sig),
			Message:   &bytes.Buffer{},
			Slot:      piv.SlotCardAuthentication,
		})
		assert.Error(t, err)
	})

	t.Run("unexpected PEM header", func(t *testing.T) {
		sig, err := Sign(yk, &SignOpts{
			StatusFd:           0,
			Detach:             false,
			Armor:              true,
			UserId:             fingerprint,
			TimestampAuthority: "",
			Message:            &bytes.Buffer{},
			Slot:               piv.SlotCardAuthentication,
		})
		if err != nil {
			t.Fatal(err)
		}
		block, _ := pem.Decode(sig)
		sig = pem.EncodeToMemory(&pem.Block{
			Type:  "UNEXPECTED",
			Bytes: block.Bytes,
		})
		err = VerifySignature(yk, &VerifyOpts{
			Signature: bytes.NewReader(sig),
			Message:   &bytes.Buffer{},
			Slot:      piv.SlotCardAuthentication,
		})
		assert.Error(t, err)
	})

	t.Run("bad detach signature", func(t *testing.T) {
		sig, err := Sign(yk, &SignOpts{
			StatusFd:           0,
			Detach:             true,
			Armor:              false,
			UserId:             fingerprint,
			TimestampAuthority: "",
			Message:            &bytes.Buffer{},
			Slot:               piv.SlotCardAuthentication,
		})
		if err != nil {
			t.Fatal(err)
		}
		err = VerifySignature(yk, &VerifyOpts{
			Signature: bytes.NewReader(sig),
			Message:   bytes.NewReader([]byte("not the same signed message")),
			Slot:      piv.SlotCardAuthentication,
		})
		assert.Error(t, err)
	})
}
