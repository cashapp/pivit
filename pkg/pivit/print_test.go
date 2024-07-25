package pivit

import (
	"testing"

	"github.com/go-piv/piv-go/piv"
	"github.com/stretchr/testify/assert"
)

func TestPrintCertificate(t *testing.T) {
	yk, err := testYubikey()
	if err != nil {
		t.Fatal(err)
	}

	opts := &PrintCertificateOpts{
		Slot: piv.SlotCardAuthentication,
	}
	err = PrintCertificate(yk, opts)
	assert.Error(t, err, "key not found")

	_, err = yk.GenerateKey(piv.DefaultManagementKey, piv.SlotCardAuthentication, piv.Key{})
	if err != nil {
		t.Fatal(err)
	}

	err = PrintCertificate(yk, opts)
	assert.NoError(t, err)
}
