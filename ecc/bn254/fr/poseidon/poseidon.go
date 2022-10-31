package poseidon

import (
	"errors"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/poseidon/constants"
	"hash"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

const (
	BlockSize = fr.Bytes // BlockSize size that mimc consumes
)

func zeroElement() *fr.Element {
	return &fr.Element{0, 0, 0, 0}
}

func deepCopy(dst, src []*fr.Element) {
	if len(src) > len(dst) {
		panic("Cannot copy to a smaller destination")
	}
	for i := 0; i < len(src); i++ {
		v := *src[i]
		dst[i] = &v
	}
}

// MDS matrix multiply mds * state
func mix(state []*fr.Element) []*fr.Element {
	width := len(state)
	index := width - 3
	newState := make([]*fr.Element, width)
	for i := 0; i < width; i++ {
		acc := zeroElement()
		for j := 0; j < width; j++ {
			acc.Add(acc, zeroElement().Mul(constants.MDS[index][i][j], state[j]))
		}
		newState[i] = acc
	}
	return newState
}

func fullRounds(state []*fr.Element, roundCounter *int) []*fr.Element {
	width := len(state)
	index := width - 3
	rf := constants.RF / 2
	for i := 0; i < rf; i++ {
		for j := 0; j < width; j++ {
			// Add round constants
			state[j].Add(state[j], constants.RC[index][*roundCounter])
			*roundCounter += 1
			// Apply full s-box
			state[j].Exp(*state[j], constants.Alpha)
		}
		// Apply mix layer
		state = mix(state)
	}
	return state
}

func partialRounds(state []*fr.Element, roundCounter *int) []*fr.Element {
	width := len(state)
	index := width - 3
	for i := 0; i < constants.RP[index]; i++ {
		for j := 0; j < width; j++ {
			// Add round constants
			state[j].Add(state[j], constants.RC[index][*roundCounter])
			*roundCounter += 1
		}
		// Apply single s-box
		state[0].Exp(*state[0], constants.Alpha)
		// Apply mix layer
		state = mix(state)
	}
	return state
}

func permutation(state []*fr.Element) []*fr.Element {
	roundCounter := 0
	state = fullRounds(state, &roundCounter)
	state = partialRounds(state, &roundCounter)
	state = fullRounds(state, &roundCounter)
	return state
}

func Poseidon(input ...*fr.Element) *fr.Element {
	inputLength := len(input)
	// No support for hashing inputs of length less than 2
	if inputLength < 2 {
		panic("Not supported input size")
	}

	const maxLength = 12
	state := make([]*fr.Element, maxLength+1)
	state[0] = zeroElement()
	startIndex := 0
	lastIndex := 0

	// Make a hash chain of the input if its length > maxLength
	if inputLength > maxLength {
		count := inputLength / maxLength
		for i := 0; i < count; i++ {
			lastIndex = (i + 1) * maxLength
			deepCopy(state[1:], input[startIndex:lastIndex])
			state = permutation(state)
			startIndex = lastIndex
		}
	}

	// For the remaining part of the input OR if 2 <= inputLength <= 12
	if lastIndex < inputLength {
		lastIndex = inputLength
		remainigLength := lastIndex - startIndex
		deepCopy(state[1:], input[startIndex:lastIndex])
		state = permutation(state[:remainigLength+1])
	}
	return state[0]
}

func PoseidonBytes(input ...[]byte) []byte {
	inputElements := make([]*fr.Element, len(input))
	for i, ele := range input {
		num := new(big.Int).SetBytes(ele)
		if num.Cmp(fr.Modulus()) >= 0 {
			panic("not support bytes bigger than modulus")
		}
		e := fr.Element{0, 0, 0, 0}
		e.SetBigInt(new(big.Int).SetBytes(ele))
		inputElements[i] = &e
	}
	res := Poseidon(inputElements...).Bytes()
	return res[:]
}

type digest struct {
	h    fr.Element
	data [][]byte // data to hash
}

func NewPoseidon() hash.Hash {
	d := new(digest)
	d.Reset()
	return d
}

// Reset resets the Hash to its initial state.
func (d *digest) Reset() {
	d.data = nil
	d.h = fr.Element{0, 0, 0, 0}
}

// Only receive byte slice less than fr.Modulus()
func (d *digest) Write(p []byte) (n int, err error) {
	n = len(p)
	num := new(big.Int).SetBytes(p)
	if num.Cmp(fr.Modulus()) >= 0 {
		return 0, errors.New("not support bytes bigger than modulus")
	}
	d.data = append(d.data, p)
	return n, nil
}

func (d *digest) Size() int {
	return BlockSize
}

// BlockSize returns the number of bytes Sum will return.
func (d *digest) BlockSize() int {
	return BlockSize
}

// Sum appends the current hash to b and returns the resulting slice.
// It does not change the underlying hash state.
func (d *digest) Sum(b []byte) []byte {
	e := fr.Element{0, 0, 0, 0}
	e.SetBigInt(new(big.Int).SetBytes(PoseidonBytes(d.data...)))
	d.h = e
	d.data = nil // flush the data already hashed
	hash := d.h.Bytes()
	b = append(b, hash[:]...)
	return b
}
