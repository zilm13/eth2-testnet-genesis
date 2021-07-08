package main

import (
	"encoding/hex"
	"github.com/ethereum/go-ethereum/common"
	hdwallet "github.com/miguelmota/go-ethereum-hdwallet"
	"github.com/stretchr/testify/require"
	"gotest.tools/assert"
	"math/big"
	"testing"
)

func _byteArray(input string) []byte {
	res, _ := hex.DecodeString(input)
	return res
}

func TestDeriveChildKey(t *testing.T) {
	seed := _byteArray("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
	tests := []struct {
		name       string
		seed       []byte
		childIndex uint64
		childSK    *big.Int
		address    common.Address
	}{
		{
			name:       "Good1",
			seed:       seed,
			childIndex: uint64(1),
			address:    common.HexToAddress("600334763B653C8A405bF3068B23F14761b14bA9"),
		},
		{
			name:       "Good2",
			seed:       seed,
			childIndex: uint64(2),
			address:    common.HexToAddress("5a71A72eb5FF93Ab05DD5422c419A86775C3662F"),
		},
		{
			name:       "Good3",
			seed:       seed,
			childIndex: uint64(3),
			address:    common.HexToAddress("49541bef9F11175AD96a1c9d48707bfF241FE5FA"),
		},
		{
			name:       "Good4",
			seed:       seed,
			childIndex: uint64(4),
			address:    common.HexToAddress("70839F216C15C89EE3A0cCeBeceF5ecD286289bB"),
		},
		{
			name:       "Good5",
			seed:       seed,
			childIndex: uint64(5),
			address:    common.HexToAddress("3592E66FCDb6cCdbbEFd5Ec2dF8A6279735bB9b1"),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			wallet, err := hdwallet.NewFromSeed(test.seed)
			require.Nil(t, err)
			childPath := deriveEth1Path(test.childIndex)
			childAccount, err := wallet.Derive(childPath, false)
			require.Nil(t, err)
			//fmt.Println(AddressToHex(PubkeyToAddress(priv.PublicKey)))
			assert.Equal(t, test.address, childAccount.Address)
		})
	}
}
