package main

import (
	"encoding/hex"
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
	tests := []struct {
		name       string
		seed       []byte
		childIndex uint32
		err        error
		childSK    *big.Int
		address    Address
	}{
		{
			name:       "Good1",
			seed:       _byteArray("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"),
			childIndex: uint32(1),
			childSK:    _bigInt("27952832856699425927396276047582405243509257097920394320299129374879708144918"),
			address:    HexToAddress("4b19f1b5088d62e7ea6332923e477d9455e5c659"),
		},
		{
			name:       "Good2",
			seed:       _byteArray("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"),
			childIndex: uint32(2),
			childSK:    _bigInt("35509587298904250182740419687797738401328614875710256124364657536795208059955"),
			address:    HexToAddress("97c5a579b62ae74bfe796e96af9a3edec0f0d525"),
		},
		{
			name:       "Good3",
			seed:       _byteArray("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"),
			childIndex: uint32(3),
			childSK:    _bigInt("26930645899403624230189009537970227926486224305892215843631536671422299745401"),
			address:    HexToAddress("7d221c84d81695df6c0c7473f9c59cf3cb610263"),
		},
		{
			name:       "Good4",
			seed:       _byteArray("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"),
			childIndex: uint32(4),
			childSK:    _bigInt("10290988197666093315250056138431207449644593233785312842213474355543058456160"),
			address:    HexToAddress("b594517a9509ef708cf0e21af72da020e7249aef"),
		},
		{
			name:       "Good5",
			seed:       _byteArray("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"),
			childIndex: uint32(5),
			childSK:    _bigInt("33732672210150861497205005541297562622200130140037536914477000174690486234165"),
			address:    HexToAddress("fdad0ba0cfd16e58131e53b0f63e98979d478fcf"),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			masterSK, err := DeriveMasterSK(test.seed)
			require.Nil(t, err)
			childSK, err := DeriveChildSK(masterSK, test.childIndex)
			if test.err != nil {
				require.NotNil(t, err)
				require.Equal(t, test.err.Error(), err.Error())
			} else {
				require.Nil(t, err)
				//fmt.Println(childSK)
				assert.Equal(t, test.childSK.Cmp(childSK), 0)
				priv, err := ToECDSA(test.childSK.Bytes())
				require.Nil(t, err)
				//fmt.Println(AddressToHex(PubkeyToAddress(priv.PublicKey)))
				assert.Equal(t, test.address, PubkeyToAddress(priv.PublicKey))
			}
		})
	}
}
