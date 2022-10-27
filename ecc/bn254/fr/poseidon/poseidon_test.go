package poseidon

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/stretchr/testify/assert"
)

func TestPoseidonTwo(t *testing.T) {
	// Test vector https://extgit.iaik.tugraz.at/krypto/hadeshash/-/blob/master/code/test_vectors.txt
	inputsStr := []string{"1", "2"}
	expectedHash := fr.FromHex("115cc0f5e7d690413df64c6b9662e9cf2a3617f2743245519e19607a4417189a")
	inputs := make([]*fr.Element, len(inputsStr))
	for i := 0; i < len(inputsStr); i++ {
		inputs[i] = fr.FromHex(inputsStr[i])
	}
	actualHash := Poseidon(inputs...)
	assert.True(t, actualHash.Equal(expectedHash), "%s != %s", actualHash, expectedHash)
}

func TestPoseidonFour(t *testing.T) {
	// Test vector https://extgit.iaik.tugraz.at/krypto/hadeshash/-/blob/master/code/test_vectors.txt
	inputsStr := []string{"1", "2", "3", "4"}
	expectedHash := fr.FromHex("299c867db6c1fdd79dcefa40e4510b9837e60ebb1ce0663dbaa525df65250465")
	inputs := make([]*fr.Element, len(inputsStr))
	for i := 0; i < len(inputsStr); i++ {
		inputs[i] = fr.FromHex(inputsStr[i])
	}
	actualHash := Poseidon(inputs...)
	assert.True(t, actualHash.Equal(expectedHash), "%s != %s", actualHash, expectedHash)
}

func TestPoseidonThirty(t *testing.T) {
	// WARNING: No test vector to compare with
	expectedHash := fr.FromHex("140CEA90C05A04C7140337789BD4CDE38BA73EE1988D34533F3F8F7B6AAC5675")
	length := 30
	inputs := make([]*fr.Element, length)
	for i := 0; i < length; i++ {
		e := fr.NewElement((uint64)(i + 1))
		inputs[i] = &e
	}
	actualHash := Poseidon(inputs...)
	assert.True(t, actualHash.Equal(expectedHash), "%s != %s", actualHash, expectedHash)
}
