package main

import (
	"crypto/rand"
	"fmt"
	"math/big"

	"github.com/cashapp/pivit/cmd/pivit/utils"
	"github.com/go-piv/piv-go/piv"
	"github.com/pkg/errors"
)

// commandReset resets the yubikey, sets a new pin, and sets a random PIN unblock key
func commandReset() error {
	cards, err := piv.Cards()
	if err != nil {
		return errors.Wrap(err, "enumerate smart cards")
	}
	if len(cards) != 1 {
		return errors.New("no smart card found")
	}

	yk, err := piv.Open(cards[0])
	if err != nil {
		return errors.Wrap(err, "open smart card")
	}
	defer func() {
		_ = yk.Close()
	}()

	if err = yk.Reset(); err != nil {
		return errors.Wrap(err, "reset PIV applet")
	}

	newPin, err := utils.GetPin()
	if err != nil {
		return errors.Wrap(err, "get pin")
	}

	if err = yk.SetPIN(piv.DefaultPIN, newPin); err != nil {
		return errors.Wrap(err, "failed to change pin")
	}

	newManagementKey := deriveManagementKey(newPin)
	if err = yk.SetManagementKey(piv.DefaultManagementKey, *newManagementKey); err != nil {
		return errors.Wrap(err, "set new management key")
	}

	randomPuk, err := rand.Int(rand.Reader, big.NewInt(100_000_000))
	if err != nil {
		return errors.Wrap(err, "create new random puk")
	}

	if err = yk.SetPUK(piv.DefaultPUK, fmt.Sprintf("%08d", randomPuk)); err != nil {
		return errors.Wrap(err, "set new puk")
	}

	return nil
}
