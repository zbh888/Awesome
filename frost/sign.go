package frost

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
	r := Response{1,ToScalar(1)}
	return r
}

func SA_GenerateSignature(message string, B []PairOfNonceCommitments, responses []Response) Signature {
	var sig Signature
	return sig
}