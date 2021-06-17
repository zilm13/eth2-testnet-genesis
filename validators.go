package main

import (
	ecdsa "crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"github.com/ethereum/go-ethereum/crypto/secp256k1"
	"github.com/pkg/errors"
	"github.com/protolambda/zrnt/eth2/beacon/common"
	"github.com/protolambda/zrnt/eth2/beacon/phase0"
	"github.com/tyler-smith/go-bip39"
	"github.com/wealdtech/go-bytesutil"
	util "github.com/wealdtech/go-eth2-util"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/sha3"
	"gopkg.in/yaml.v3"
	"hash"
	"math/big"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// TODO: REFACTOR ME, MY EYES ARE BLEEDING
var (
	r = _bigInt("52435875175126190479447740508185965837690552500527637822603658699938581184513")
	// 48 comes from ceil((1.5 * ceil(log2(r))) / 8)
	l             = 32
	secp256k1N, _ = new(big.Int).SetString("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", 16)
	// AddressLength is the expected length of the address
)

const (
	AddressLength = 20
)

func _bigInt(input string) *big.Int {
	result, _ := new(big.Int).SetString(input, 10)
	return result
}

// Address represents the 20 byte address of an Ethereum account.
type Address [AddressLength]byte

func HexToAddress(s string) Address { return BytesToAddress(FromHex(s)) }

func AddressToHex(a Address) string { return hex.EncodeToString(a.GetBytes()) }

// FromHex returns the bytes represented by the hexadecimal string s.
// s may be prefixed with "0x".
func FromHex(s string) []byte {
	if has0xPrefix(s) {
		s = s[2:]
	}
	if len(s)%2 == 1 {
		s = "0" + s
	}
	return Hex2Bytes(s)
}

// Hex2Bytes returns the bytes represented by the hexadecimal string str.
func Hex2Bytes(str string) []byte {
	h, _ := hex.DecodeString(str)
	return h
}

// has0xPrefix validates str begins with '0x' or '0X'.
func has0xPrefix(str string) bool {
	return len(str) >= 2 && str[0] == '0' && (str[1] == 'x' || str[1] == 'X')
}

// SetBytes sets the address to the value of b.
// If b is larger than len(a) it will panic.
func (a *Address) SetBytes(b []byte) {
	if len(b) > len(a) {
		b = b[len(b)-AddressLength:]
	}
	copy(a[AddressLength-len(b):], b)
}

// GetBytes retrieves the byte representation of the address.
func (a *Address) GetBytes() []byte {
	return a[:]
}

// BytesToAddress returns Address with value b.
// If b is larger than len(h), b will be cropped from the left.
func BytesToAddress(b []byte) Address {
	var a Address
	a.SetBytes(b)
	return a
}

func FromECDSAPub(pub *ecdsa.PublicKey) []byte {
	if pub == nil || pub.X == nil || pub.Y == nil {
		return nil
	}
	return elliptic.Marshal(S256(), pub.X, pub.Y)
}

// KeccakState wraps sha3.state. In addition to the usual hash methods, it also supports
// Read to get a variable amount of data from the hash state. Read is faster than Sum
// because it doesn't copy the internal state, but also modifies the internal state.
type KeccakState interface {
	hash.Hash
	Read([]byte) (int, error)
}

// Keccak256 calculates and returns the Keccak256 hash of the input data.
func Keccak256(data ...[]byte) []byte {
	b := make([]byte, 32)
	d := sha3.NewLegacyKeccak256().(KeccakState)
	for _, b := range data {
		d.Write(b)
	}
	d.Read(b)
	return b
}

func PubkeyToAddress(p ecdsa.PublicKey) Address {
	pubBytes := FromECDSAPub(&p)
	return BytesToAddress(Keccak256(pubBytes[1:])[12:])
}

// ECDSAPrivateKeyFromSeedAndPath generates a ecdsa Private key given a seed and a path.
// Follows nothing
// Not sure BLS master to child deriving works here
func ECDSAPrivateKeyFromSeedAndPath(seed []byte, path string) (*ecdsa.PrivateKey, error) {
	if path == "" {
		return nil, errors.New("no path")
	}
	if len(seed) < 16 {
		return nil, errors.New("seed must be at least 128 bits")
	}
	pathBits := strings.Split(path, "/")
	var sk *big.Int
	var err error
	for i := range pathBits {
		if pathBits[i] == "" {
			return nil, fmt.Errorf("no entry at path component %d", i)
		}
		if pathBits[i] == "m" {
			if i != 0 {
				return nil, fmt.Errorf("invalid master at path component %d", i)
			}
			sk, err = DeriveMasterSK(seed)
			if err != nil {
				return nil, errors.Wrapf(err, "failed to generate master key at path component %d", i)
			}
		} else {
			if i == 0 {
				return nil, fmt.Errorf("not master at path component %d", i)
			}
			index, err := strconv.ParseUint(pathBits[i], 10, 32)
			if err != nil {
				return nil, fmt.Errorf("invalid index %q at path component %d", pathBits[i], i)
			}
			sk, err = DeriveChildSK(sk, uint32(index))
			if err != nil {
				return nil, errors.Wrapf(err, "failed to derive child SK at path component %d", i)
			}
		}
	}

	// SK can be shorter than 32 bytes so left-pad it here.
	bytes := make([]byte, 32)
	skBytes := sk.Bytes()
	copy(bytes[32-len(skBytes):], skBytes)

	return ToECDSA(bytes)
}

// ToECDSA creates a private key with the given D value.
func ToECDSA(d []byte) (*ecdsa.PrivateKey, error) {
	return toECDSA(d, true)
}

// S256 returns an instance of the secp256k1 curve.
func S256() elliptic.Curve {
	return secp256k1.S256()
}

// toECDSA creates a private key with the given D value. The strict parameter
// controls whether the key's length should be enforced at the curve size or
// it can also accept legacy encodings (0 prefixes).
func toECDSA(d []byte, strict bool) (*ecdsa.PrivateKey, error) {
	priv := new(ecdsa.PrivateKey)
	priv.PublicKey.Curve = S256()
	if strict && 8*len(d) != priv.Params().BitSize {
		return nil, fmt.Errorf("invalid length, need %d bits", priv.Params().BitSize)
	}
	priv.D = new(big.Int).SetBytes(d)

	// The priv.D must < N
	if priv.D.Cmp(secp256k1N) >= 0 {
		return nil, fmt.Errorf("invalid private key, >=N")
	}
	// The priv.D must not be zero or negative.
	if priv.D.Sign() <= 0 {
		return nil, fmt.Errorf("invalid private key, zero or negative")
	}

	priv.PublicKey.X, priv.PublicKey.Y = priv.PublicKey.Curve.ScalarBaseMult(d)
	if priv.PublicKey.X == nil {
		return nil, errors.New("invalid private key")
	}
	return priv, nil
}

// DeriveMasterSK derives the master secret key from a seed.
// Follows ERC-2333.
func DeriveMasterSK(seed []byte) (*big.Int, error) {
	if len(seed) < 16 {
		return nil, errors.New("seed must be at least 128 bits")
	}
	return hkdfModR(seed, "")
}

// DeriveChildSK derives the child secret key from a parent key.
// Follows ERC-2333.
func DeriveChildSK(parentSK *big.Int, index uint32) (*big.Int, error) {
	pk, err := parentSKToLamportPK(parentSK, index)
	if err != nil {
		return nil, err
	}
	return hkdfModR(pk, "")
}

// parentSKToLamportPK generates the Lamport private key from a BLS secret key.
func parentSKToLamportPK(parentSK *big.Int, index uint32) ([]byte, error) {
	salt := i2OSP(big.NewInt(int64(index)), 4)
	ikm := i2OSP(parentSK, 32)
	lamport0, err := ikmToLamportSK(ikm, salt)
	if err != nil {
		return nil, err
	}
	notIKM := bytesutil.XOR(ikm)
	lamport1, err := ikmToLamportSK(notIKM, salt)
	if err != nil {
		return nil, err
	}
	lamportPK := make([]byte, (255+255)*32)
	for i := 0; i < 255; i++ {
		copy(lamportPK[32*i:], SHA256(lamport0[i][:]))
	}
	for i := 0; i < 255; i++ {
		copy(lamportPK[(i+255)*32:], SHA256(lamport1[i][:]))
	}
	compressedLamportPK := SHA256(lamportPK)
	return compressedLamportPK, nil
}

// ikmToLamportSK creates a Lamport secret key.
func ikmToLamportSK(ikm []byte, salt []byte) ([255][32]byte, error) {
	prk := hkdf.Extract(sha256.New, ikm, salt)
	okm := hkdf.Expand(sha256.New, prk, nil)
	var lamportSK [255][32]byte
	for i := 0; i < 255; i++ {
		var result [32]byte
		read, err := okm.Read(result[:])
		if err != nil {
			return lamportSK, err
		}
		if read != 32 {
			return lamportSK, fmt.Errorf("only read %d bytes", read)
		}
		lamportSK[i] = result
	}

	return lamportSK, nil
}

// hkdfModR hashes 32 random bytes into the subgroup of the BLS12-381 private keys.
func hkdfModR(ikm []byte, keyInfo string) (*big.Int, error) {
	salt := []byte("ECDSA-SIG-KEYGEN-SALT-")
	sk := big.NewInt(0)
	for sk.Cmp(big.NewInt(0)) == 0 {
		salt = SHA256(salt)
		prk := hkdf.Extract(sha256.New, append(ikm, i2OSP(big.NewInt(0), 1)...), salt)
		okm := hkdf.Expand(sha256.New, prk, append([]byte(keyInfo), i2OSP(big.NewInt(int64(l)), 2)...))
		okmOut := make([]byte, l)
		read, err := okm.Read(okmOut)
		if err != nil {
			return nil, err
		}
		if read != l {
			return nil, fmt.Errorf("only read %d bytes", read)
		}
		sk = new(big.Int).Mod(osToIP(okmOut), r)
	}
	return sk, nil
}

// SHA256 creates an SHA-256 hash of the supplied data
func SHA256(data ...[]byte) []byte {
	hash := sha256.New()
	for _, d := range data {
		_, _ = hash.Write(d)
	}
	return hash.Sum(nil)
}

// osToIP turns a byte array in to an integer as per https://ietf.org/rfc/rfc3447.txt
func osToIP(data []byte) *big.Int {
	return new(big.Int).SetBytes(data)
}

// i2OSP turns an integer in to a byte array as per https://ietf.org/rfc/rfc3447.txt
func i2OSP(data *big.Int, resLen int) []byte {
	res := make([]byte, resLen)
	bytes := data.Bytes()
	copy(res[resLen-len(bytes):], bytes)
	return res
}

func loadValidatorKeys(spec *common.Spec, mnemonicsConfigPath string, tranchesDir string) ([]phase0.KickstartValidatorData, error) {
	mnemonics, err := loadMnemonics(mnemonicsConfigPath)
	if err != nil {
		return nil, err
	}

	var validators []phase0.KickstartValidatorData
	for m, mnemonicSrc := range mnemonics {
		fmt.Printf("processing mnemonic %d, for %d validators\n", m, mnemonicSrc.Count)
		seed, err := seedFromMnemonic(mnemonicSrc.Mnemonic)
		if err != nil {
			return nil, fmt.Errorf("mnemonic %d is bad", m)
		}
		pubs := make([]string, 0, mnemonicSrc.Count)
		for i := uint64(0); i < mnemonicSrc.Count; i++ {
			if i%100 == 0 {
				fmt.Printf("...validator %d/%d\n", i, mnemonicSrc.Count)
			}
			signingKey, err := util.PrivateKeyFromSeedAndPath(seed, validatorKeyName(i))
			if err != nil {
				return nil, err
			}
			// TODO: change path
			withdrawalAddressKey, err := ECDSAPrivateKeyFromSeedAndPath(seed, withdrawalKeyName(i))
			if err != nil {
				return nil, err
			}

			// BLS signing key
			var data phase0.KickstartValidatorData
			copy(data.Pubkey[:], signingKey.PublicKey().Marshal())
			pubs = append(pubs, data.Pubkey.String())

			// Eth1 address withdrawal credentials
			address := PubkeyToAddress(withdrawalAddressKey.PublicKey)
			copy(data.WithdrawalCredentials[12:], address.GetBytes())
			data.WithdrawalCredentials[0] = 1

			// Max effective balance by default for activation
			data.Balance = spec.MAX_EFFECTIVE_BALANCE

			validators = append(validators, data)
		}
		fmt.Println("Writing pubkeys list file...")
		if err := outputPubkeys(filepath.Join(tranchesDir, fmt.Sprintf("tranche_%04d.txt", m)), pubs); err != nil {
			return nil, err
		}
	}
	return validators, nil
}

func validatorKeyName(i uint64) string {
	return fmt.Sprintf("m/12381/3600/%d/0/0", i)
}

func withdrawalKeyName(i uint64) string {
	return fmt.Sprintf("m/12381/3600/%d/0", i)
}

func seedFromMnemonic(mnemonic string) (seed []byte, err error) {
	mnemonic = strings.TrimSpace(mnemonic)
	if !bip39.IsMnemonicValid(mnemonic) {
		return nil, errors.New("mnemonic is not valid")
	}
	return bip39.NewSeed(mnemonic, ""), nil
}

func outputPubkeys(outPath string, data []string) error {
	f, err := os.OpenFile(outPath, os.O_CREATE|os.O_WRONLY, 0777)
	if err != nil {
		return err
	}
	defer f.Close()
	for _, p := range data {
		if _, err := f.WriteString(p + "\n"); err != nil {
			return err
		}
	}
	return nil
}

type MnemonicSrc struct {
	Mnemonic string `yaml:"mnemonic"`
	Count    uint64 `yaml:"count"`
}

func loadMnemonics(srcPath string) ([]MnemonicSrc, error) {
	f, err := os.Open(srcPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var data []MnemonicSrc
	dec := yaml.NewDecoder(f)
	if err := dec.Decode(&data); err != nil {
		return nil, err
	}
	return data, nil
}
