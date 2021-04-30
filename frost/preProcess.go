package frost

import (
	"errors"
	ed "gitlab.com/polychainlabs/threshold-ed25519/pkg"
)

func PreProcess(index uint32, numSigns int) (PairOfNonceCommitmentsList, []TwoPairOfNonceCommitmentAndNonce, error) {
	var Save []TwoPairOfNonceCommitmentAndNonce
	if numSigns < 1 {
		return PairOfNonceCommitmentsList{}, Save, errors.New("numSigns should be greater than 0")
	}
	if index < 1 {
		return PairOfNonceCommitmentsList{}, Save, errors.New("index should be greater than 0")
	}
	var L []PairOfNonceCommitments
	var i int
	for i = 0; i < numSigns; i++ {
		d := RandomGenerator()
		e := RandomGenerator()
		D := ed.ScalarMultiplyBase(d)
		E := ed.ScalarMultiplyBase(e)
		PairCommitments := PairOfNonceCommitments{index,D,E}
		StoringCommitments := TwoPairOfNonceCommitmentAndNonce{d,D,e,E}
		L = append(L, PairCommitments)
		Save = append(Save, StoringCommitments)
	}
	List := PairOfNonceCommitmentsList{index, L}
	return List, Save, nil
}


