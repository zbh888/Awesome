package frost

import ed "gitlab.com/polychainlabs/threshold-ed25519/pkg"

func PreProcess(index uint32, numSigns int) (PairOfNonceCommitmentsList, []TwoPairOfNonceCommitmentAndNonce) {
	var L []PairOfNonceCommitments
	var Save []TwoPairOfNonceCommitmentAndNonce
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
	return List, Save
}


