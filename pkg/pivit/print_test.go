package pivit

import (
	"testing"

	"github.com/go-piv/piv-go/v2/piv"
	"github.com/stretchr/testify/assert"
)

func TestCertificate_errEmptyYubikey(t *testing.T) {
	yk, err := testYubikey()
	if err != nil {
		t.Fatal(err)
	}

	opts := &CertificateOpts{
		Slot: piv.SlotCardAuthentication,
	}
	_, err = Certificate(yk, opts)
	assert.Error(t, err, "key not found")
}

func TestPrintCertificate_success(t *testing.T) {
	yk, err := testYubikey()
	if err != nil {
		t.Fatal(err)
	}

	_, err = yk.GenerateKey(piv.DefaultManagementKey, piv.SlotCardAuthentication, piv.Key{Algorithm: piv.AlgorithmRSA4096})
	if err != nil {
		t.Fatal(err)
	}

	cert, err := yk.Attest(piv.SlotCardAuthentication)
	if err != nil {
		t.Fatal(err)
	}

	err = yk.SetCertificate(piv.DefaultManagementKey, piv.SlotCardAuthentication, cert)
	if err != nil {
		t.Fatal(err)
	}

	opts := &CertificateOpts{
		Slot: piv.SlotCardAuthentication,
	}
	output, err := Certificate(yk, opts)
	assert.NoError(t, err)
	assert.NotEmpty(t, output.Fingerprint)
	assert.NotNil(t, output.CertificatePem)
}
