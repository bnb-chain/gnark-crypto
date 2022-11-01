package poseidon

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/stretchr/testify/assert"
)

func elementFromHexString(v string) *fr.Element {
	n, success := new(big.Int).SetString(v, 16)
	if !success {
		panic("Error parsing hex number")
	}
	e := fr.Element{0, 0, 0, 0}
	e.SetBigInt(n)
	return &e
}

func TestPoseidonTwo(t *testing.T) {
	// Test vector https://extgit.iaik.tugraz.at/krypto/hadeshash/-/blob/master/code/test_vectors.txt
	inputsStr := []string{"1", "2"}
	expectedHash := elementFromHexString("115cc0f5e7d690413df64c6b9662e9cf2a3617f2743245519e19607a4417189a")
	inputs := make([]*fr.Element, len(inputsStr))
	for i := 0; i < len(inputsStr); i++ {
		inputs[i] = elementFromHexString(inputsStr[i])
	}
	actualHash := Poseidon(inputs...)
	assert.True(t, actualHash.Equal(expectedHash), "%s != %s", actualHash, expectedHash)
}

func TestPoseidonFour(t *testing.T) {
	// Test vector https://extgit.iaik.tugraz.at/krypto/hadeshash/-/blob/master/code/test_vectors.txt
	inputsStr := []string{"1", "2", "3", "4"}
	expectedHash := elementFromHexString("299c867db6c1fdd79dcefa40e4510b9837e60ebb1ce0663dbaa525df65250465")
	inputs := make([]*fr.Element, len(inputsStr))
	for i := 0; i < len(inputsStr); i++ {
		inputs[i] = elementFromHexString(inputsStr[i])
	}
	actualHash := Poseidon(inputs...)
	assert.True(t, actualHash.Equal(expectedHash), "%s != %s", actualHash, expectedHash)
}

func TestPoseidon24(t *testing.T) {
	// WARNING: No test vector to compare with
	expectedHash := elementFromHexString("612D378F91DC3422E6C60E54D24E3FA6D8000F0E47CDACE9BDB304506E3C9D3")
	length := 24
	inputs := make([]*fr.Element, length)
	for i := 0; i < length; i++ {
		e := fr.NewElement((uint64)(i + 1))
		inputs[i] = &e
	}
	actualHash := Poseidon(inputs...)
	assert.True(t, actualHash.Equal(expectedHash), "%s != %s", actualHash, expectedHash)
}

func TestPoseidonThirty(t *testing.T) {
	// WARNING: No test vector to compare with
	expectedHash := elementFromHexString("140CEA90C05A04C7140337789BD4CDE38BA73EE1988D34533F3F8F7B6AAC5675")
	length := 30
	inputs := make([]*fr.Element, length)
	for i := 0; i < length; i++ {
		e := fr.NewElement((uint64)(i + 1))
		inputs[i] = &e
	}
	actualHash := Poseidon(inputs...)
	assert.True(t, actualHash.Equal(expectedHash), "%s != %s", actualHash, expectedHash)
}

func TestConsistency(t *testing.T) {
	// Check whether Poseidon returns the same value for the same input
	// Test vector https://extgit.iaik.tugraz.at/krypto/hadeshash/-/blob/master/code/test_vectors.txt
	inputsStr := []string{"1", "2", "3", "4"}
	inputs := make([]*fr.Element, len(inputsStr))
	for i := 0; i < len(inputsStr); i++ {
		inputs[i] = elementFromHexString(inputsStr[i])
	}
	actualHash1 := Poseidon(inputs...)
	actualHash2 := Poseidon(inputs...)
	assert.True(t, actualHash1.Equal(actualHash2), "%s != %s", actualHash1, actualHash2)
}

func TestPoseidonBytes(t *testing.T) {
	// Test vector https://extgit.iaik.tugraz.at/krypto/hadeshash/-/blob/master/code/test_vectors.txt
	expectedHash := elementFromHexString("115cc0f5e7d690413df64c6b9662e9cf2a3617f2743245519e19607a4417189a")
	inputs := make([][]byte, 2)
	inputs[0] = make([]byte, 1)
	inputs[0][0] = 1
	inputs[1] = make([]byte, 1)
	inputs[1][0] = 2
	actualHash := PoseidonBytes(inputs...)
	actualHashEle := fr.Element{0, 0, 0, 0}
	actualHashEle.SetBytes(actualHash)
	assert.True(t, actualHashEle.Equal(expectedHash), "%s != %s", actualHashEle, expectedHash)
}

func TestDigest(t *testing.T) {
	expectedHash := elementFromHexString("115cc0f5e7d690413df64c6b9662e9cf2a3617f2743245519e19607a4417189a")
	hFunc := NewPoseidon()
	inputs := make([][]byte, 2)
	inputs[0] = make([]byte, 1)
	inputs[0][0] = 1
	inputs[1] = make([]byte, 1)
	inputs[1][0] = 2
	hFunc.Write(inputs[0])
	hFunc.Write(inputs[1])
	actualHash := hFunc.Sum(nil)
	actualHashEle := fr.Element{0, 0, 0, 0}
	actualHashEle.SetBytes(actualHash)
	assert.True(t, actualHashEle.Equal(expectedHash), "%s != %s", actualHashEle, expectedHash)

	hFunc.Reset()
	bigNumber, _ := new(big.Int).SetString("21888242871839275222246405745257275088548364400416034343698204186575808495617", 10)
	inputs[0] = bigNumber.Bytes()
	n, err := hFunc.Write(inputs[0])
	assert.EqualError(t, err, "not support bytes bigger than modulus")
	assert.Equal(t, n, 0)
}
