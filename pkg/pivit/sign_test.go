package pivit

import (
	"bytes"
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
	err = GenerateCertificate(yk, genOpts)
	if err != nil {
		t.Fatal(err)
	}

	cert := yk.slots[piv.SlotCardAuthentication].cert
	fingerprint := CertHexFingerprint(cert)

	testCases := []struct {
		description  string
		armor        bool
		detach       bool
		userId       string
		timestampUrl string
		slot         piv.Slot
		expectError  bool
	}{
		{
			description:  "no certificate found",
			armor:        false,
			detach:       false,
			userId:       "",
			timestampUrl: "",
			slot:         piv.SlotSignature,
			expectError:  true,
		},
		{
			description:  "bad fingerprint",
			armor:        false,
			detach:       false,
			userId:       "",
			timestampUrl: "",
			slot:         piv.SlotCardAuthentication,
			expectError:  true,
		},
		{
			description:  "default options",
			armor:        false,
			detach:       false,
			userId:       fingerprint,
			timestampUrl: "",
			slot:         piv.SlotCardAuthentication,
			expectError:  false,
		},
		{
			description:  "with armor",
			armor:        true,
			detach:       false,
			userId:       fingerprint,
			timestampUrl: "",
			slot:         piv.SlotCardAuthentication,
			expectError:  false,
		},
		{
			description:  "detached signature",
			armor:        false,
			detach:       true,
			userId:       fingerprint,
			timestampUrl: "",
			slot:         piv.SlotCardAuthentication,
			expectError:  false,
		},
		{
			description:  "with timestamp server",
			armor:        false,
			detach:       false,
			userId:       fingerprint,
			timestampUrl: "http://timestamp.digicert.com",
			slot:         piv.SlotCardAuthentication,
			expectError:  false,
		},
		{
			description:  "bad timestamp server",
			armor:        false,
			detach:       false,
			userId:       fingerprint,
			timestampUrl: "http://127.0.0.1",
			slot:         piv.SlotCardAuthentication,
			expectError:  true,
		},
	}
	for _, test := range testCases {
		t.Run(test.description, func(t *testing.T) {
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
			err = Sign(yk, signOpts)
			if test.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
