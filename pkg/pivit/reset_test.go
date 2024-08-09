package pivit

import (
	"testing"

	"github.com/go-piv/piv-go/piv"
	"github.com/stretchr/testify/assert"
)

func TestReset(t *testing.T) {
	yk, err := testYubikey()
	if err != nil {
		t.Fatal(err)
	}

	err = ResetYubikey(yk, &ResetOpts{
		Pin: "87654321",
	})
	if err != nil {
		t.Fatal(err)
	}

	assert.NotEqual(t, piv.DefaultPUK, yk.puk)
	assert.NotEqual(t, piv.DefaultManagementKey, yk.managementKey)
	assert.Equal(t, yk.pin, "87654321")
	assert.Equal(t, &yk.managementKey, yk.metadata.ManagementKey)
}
