package pivit

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"net"
	"net/url"
	"testing"
	"time"

	"github.com/go-piv/piv-go/piv"
	"github.com/stretchr/testify/assert"
)

func TestImportCertificate(t *testing.T) {
	yk, err := testYubikey()
	if err != nil {
		t.Fatal(err)
	}
	patchPivVerify(yk)
	defer unpatchPinVerify()

	generateResults, err := GenerateCertificate(yk, &GenerateCertificateOpts{
		Algorithm:   piv.AlgorithmEC384,
		SelfSign:    true,
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

	testCases := []struct {
		name           string
		certBytes      []byte
		stopAfterFirst bool
		slot           piv.Slot
		pin            string
		expectErr      bool
	}{
		{
			name:           "bad pin",
			certBytes:      generateResults.Certificate,
			stopAfterFirst: true,
			slot:           piv.SlotCardAuthentication,
			pin:            "654321",
			expectErr:      true,
		},
		{
			name:           "bad certificate bytes",
			certBytes:      createBadPEM(generateResults.Certificate),
			stopAfterFirst: true,
			slot:           piv.SlotCardAuthentication,
			pin:            piv.DefaultPIN,
			expectErr:      true,
		},
		{
			name:           "bad x509 certificate",
			certBytes:      createBadX509Certificate(generateResults.Certificate),
			stopAfterFirst: true,
			slot:           piv.SlotCardAuthentication,
			pin:            piv.DefaultPIN,
			expectErr:      true,
		},
		{
			name:           "empty slot",
			certBytes:      generateResults.Certificate,
			stopAfterFirst: true,
			slot:           piv.SlotSignature,
			pin:            piv.DefaultPIN,
			expectErr:      true,
		},
		{
			name:           "contains more data after cert",
			certBytes:      append(generateResults.Certificate, []byte("\nsome more data here")...),
			stopAfterFirst: false,
			slot:           piv.SlotCardAuthentication,
			pin:            piv.DefaultPIN,
			expectErr:      true,
		},
		{
			name:           "contains more data after cert but stopAfterFirst is true",
			certBytes:      append(generateResults.Certificate, []byte("\nsome more data here")...),
			stopAfterFirst: true,
			slot:           piv.SlotCardAuthentication,
			pin:            piv.DefaultPIN,
			expectErr:      false,
		},
		{
			name:           "cert and key don't match",
			certBytes:      createRandomCertificate(t),
			stopAfterFirst: true,
			slot:           piv.SlotCardAuthentication,
			pin:            piv.DefaultPIN,
			expectErr:      true,
		},
	}
	for _, test := range testCases {
		t.Run(test.name, func(t *testing.T) {
			actual := ImportCertificate(yk, &ImportOpts{
				CertificateBytes: test.certBytes,
				StopAfterFirst:   test.stopAfterFirst,
				Slot:             test.slot,
				Pin:              test.pin,
			})
			if test.expectErr {
				assert.Error(t, actual)
			} else {
				assert.NoError(t, actual)
			}
		})
	}
}

func createBadPEM(cert []byte) []byte {
	return cert[1:]
}

func createBadX509Certificate(cert []byte) []byte {
	block, _ := pem.Decode(cert)
	return pem.EncodeToMemory(&pem.Block{
		Type:  block.Type,
		Bytes: block.Bytes[1:],
	})
}

func createRandomCertificate(t *testing.T) []byte {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	subject := pkix.Name{
		Organization:       []string{"Fake Yubico."},
		OrganizationalUnit: []string{},
		SerialNumber:       "12376172635",
		CommonName:         "Fake Pivit",
	}
	extKeyUsage := []x509.ExtKeyUsage{
		x509.ExtKeyUsageClientAuth,
		x509.ExtKeyUsageCodeSigning,
	}
	serial, err := randomSerial()
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		Subject:         subject,
		SerialNumber:    serial,
		DNSNames:        []string{},
		EmailAddresses:  []string{},
		IPAddresses:     []net.IP{},
		URIs:            []*url.URL{},
		KeyUsage:        x509.KeyUsageDigitalSignature,
		ExtKeyUsage:     extKeyUsage,
		ExtraExtensions: []pkix.Extension{},
		NotBefore:       time.Now(),
		NotAfter:        time.Now().AddDate(0, 0, 1),
	}
	certBytes, err := x509.CreateCertificate(rand.Reader, template, template, priv.Public(), priv)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	})
}
