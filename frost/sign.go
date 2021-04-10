package frost

import (
	"crypto/subtle"
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

	var LagrangeCoefficient ed.Scalar = SignGenLagrangeCoefficient(index, S)

	//This block is just for r = d+(e*p)+lambda*s*c
	Intermediate := MulScalars(MulScalars(LagrangeCoefficient, keys.SecretKey), Challenge) //lambda*s*c
	d := (*save)[len(*save)-1].Nounce_d
	e := (*save)[len(*save)-1].Nonce_e
	r := AddScalars(AddScalars(d, MulScalars(e, Map_forRoh[index])), Intermediate)

	*save = (*save)[:len(*save) - 1]
	return Response{index, r}
}

// Assume Pks are all members of S
func SA_GenerateSignature(Group_PK ed.Element, message string,
	B []PairOfNonceCommitments, responses []Response, Pks []PublicKeys) (Signature, []uint32) {

	var Users []uint32
	var InvalidUsers []uint32
	var ResponseAddList []ed.Scalar
	Map_forResponse := make(map[uint32]ed.Scalar) //make a map for efficiency
	Map_forPk := make(map[uint32]ed.Element) //make a map for efficiency
	Map_forR_i := make(map[uint32]ed.Element) //make a map for efficiency
	for _, response := range responses {
		Map_forResponse[response.index] = response.value
	}
	for _, Pk := range Pks {
		Map_forPk[Pk.Index] = Pk.PublicKey
		Users = append(Users, Pk.Index)
	}

	var Signature_AddList []ed.Element
	for _, pair := range B {
		Rho := SignGenRoh(pair.Index, message,B)
		R_AddList := []ed.Element{pair.Nonce_D, ScMulElement(Rho, pair.Nonce_E)}
		R_i := ed.AddElements(R_AddList)
		Map_forR_i[pair.Index] = R_i
		Signature_AddList = append(Signature_AddList, R_i)
	}
	R := ed.AddElements(Signature_AddList)
	Challenge := SignGenChallenge(R, Group_PK, message)
	for _, index := range Users {
		CommitWithResponse := ed.ScalarMultiplyBase(Map_forResponse[index])
		left := Map_forR_i[index]
		right := ScMulElement(MulScalars(Challenge, SignGenLagrangeCoefficient(index, Users)), Map_forPk[index])
		TestValue := ed.AddElements([]ed.Element{left, right})
		if !(subtle.ConstantTimeCompare(CommitWithResponse, TestValue) == 1) {
			InvalidUsers = append(InvalidUsers, index)
		}
	}
	if len(InvalidUsers) != 0 {
		panic("No")
	}
	for _, index := range Users {
		ResponseAddList = append(ResponseAddList, Map_forResponse[index])
	}
	sig := Signature{R, ed.AddScalars(ResponseAddList)}
	return sig, InvalidUsers
}

func Verify(Signature Signature ,GroupPublicKey ed.Element, message string) string {

	Challenge := SignGenChallenge(Signature.R, GroupPublicKey, message)

	R_test := ed.AddElements([]ed.Element{ed.ScalarMultiplyBase(Signature.Z),
		ScMulElement(ScalarNeg(Challenge), GroupPublicKey)})
	if !(subtle.ConstantTimeCompare(R_test, Signature.R) == 1) {
		return "Fail to verify"
	}
	return "Success to verify"
}