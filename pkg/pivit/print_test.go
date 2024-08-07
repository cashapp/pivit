package pivit

import (
	"testing"

	"github.com/go-piv/piv-go/piv"
	"github.com/stretchr/testify/assert"
)

func TestPrintCertificate_errEmptyYubikey(t *testing.T) {
	yk, err := testYubikey()
	if err != nil {
		t.Fatal(err)
	}

	opts := &PrintCertificateOpts{
		Slot: piv.SlotCardAuthentication,
	}
	err = PrintCertificate(yk, opts)
	assert.Error(t, err, "key not found")
}

func TestPrintCertificate_success(t *testing.T) {
	yk, err := testYubikey()
	if err != nil {
		t.Fatal(err)
	}

	_, err = yk.GenerateKey(piv.DefaultManagementKey, piv.SlotCardAuthentication, piv.Key{})
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

	opts := &PrintCertificateOpts{
		Slot: piv.SlotCardAuthentication,
	}
	err = PrintCertificate(yk, opts)
	assert.NoError(t, err)
}
