package poseidon

import (
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/poseidon/constants"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

// MDS matrix multiply mds * state
func mix(state []*fr.Element) []*fr.Element {
	width := len(state)
	index := width - 3
	newState := make([]*fr.Element, width)
	for i := 0; i < width; i++ {
		acc := fr.Zero()
		for j := 0; j < width; j++ {
			acc.Add(acc, fr.Zero().Mul(constants.MDS[index][i][j], state[j]))
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
	state[0] = fr.Zero()
	startIndex := 0
	lastIndex := 0

	// Make a hash chain of the input if its length > maxLength
	if inputLength > maxLength {
		count := inputLength / maxLength
		for i := 0; i < count; i++ {
			lastIndex = (i + 1) * maxLength
			copy(state[1:], input[startIndex:lastIndex])
			state = permutation(state)
			startIndex = lastIndex
		}
	}

	// For the remaining part of the input OR if 2 <= inputLength <= 12
	lastIndex = inputLength
	remainigLength := lastIndex - startIndex
	copy(state[1:], input[startIndex:lastIndex])
	state = permutation(state[:remainigLength+1])
	return state[0]
}
