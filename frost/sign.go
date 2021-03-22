package frost

import (
	ed "gitlab.com/polychainlabs/threshold-ed25519/pkg"
)

//SA fetched the available Commitments from the server, server will handle
//the removing of Commitment and provide the correct PairOfCommitment, so SA should not care about it
func SA_GenerateB(S []uint32, message string ,AllCommitments []PairOfNonceCommitments) ([]PairOfNonceCommitments, string) {
	var B []PairOfNonceCommitments
	m := make(map[uint32]PairOfNonceCommitments) //make a map for efficiency
	for _, C := range AllCommitments {
		m[C.Index] = C
	}
	for _, index := range S {
		B = append(B, m[index])
	}
	return B, message
}

//using reference for deleting the corresponding saving share commitment
func Sign(index uint32, message string, B []PairOfNonceCommitments,
	save *[]TwoPairOfNonceCommitmentAndNonce, keys Keys) Response {
	Map_forPair := make(map[uint32]PairOfNonceCommitments) //make a map for efficiency
	Map_forRoh := make(map[uint32]ed.Scalar) //make a map for efficiency
	var S []uint32
	for _, pair := range B {
		if !IsInG(pair.Nonce_D) || !IsInG(pair.Nonce_E) {
			panic("No")
		}
		S = append(S, pair.Index)
		Map_forPair[pair.Index] = pair
		Map_forRoh[pair.Index] = SignGenRoh(pair.Index, message, B)
	}
	var ListElementForAddition []ed.Element
	for _, i := range S {
		ListElementForAddition = append(ListElementForAddition, Map_forPair[i].Nonce_D)
		ListElementForAddition = append(ListElementForAddition, ScMulElement(Map_forRoh[i],Map_forPair[i].Nonce_E))
	}
	GroupCommit := ed.AddElements(ListElementForAddition)
	Challenge := SignGenChallenge(GroupCommit, keys.GroupPublicKey,message)

	var LagRangeCoeffient ed.Scalar

	r := Response{1,ToScalar(1)}
	return r
}

func SA_GenerateSignature(message string, B []PairOfNonceCommitments, responses []Response) Signature {
	var sig Signature
	return sig
}