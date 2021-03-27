package frost

import (
	"fmt"
	ed "gitlab.com/polychainlabs/threshold-ed25519/pkg"
)

func KeyGen_send(index, threshold, NumPlayer uint32, str string) (PkgCommitment, []Share, Share) {

	var secret ed.Scalar = RandomGenerator()
	var nonce ed.Scalar = RandomGenerator()
	var nonceCommitment ed.Element = ed.ScalarMultiplyBase(nonce)
	var secretCommitment ed.Element = ed.ScalarMultiplyBase(secret)
	//generate challenge
	challenge := GenChallenge(index, str, secretCommitment, nonceCommitment)
	u := AddScalars(nonce, MulScalars(secret, challenge))

	var VecShare []Share
	var ShareSaving Share
	var PubCommitment []ed.Element
	var coefficients []ed.Scalar
	var playersIndex uint32

	// random generating coff
	for playersIndex = 1; playersIndex < threshold; playersIndex++  {
		coefficients = append(coefficients, RandomGenerator())
	}

	// create commitment (commitment size would be t)
	PubCommitment = append(PubCommitment, secretCommitment)

	for playersIndex = 0; playersIndex < threshold -1; playersIndex++  {
		PubCommitment = append(PubCommitment, ed.ScalarMultiplyBase(coefficients[playersIndex]))
	}
	Commitment := PublicCommitment {
		PubCommitment,
		index,
	}

	// generate share for other players (having n-1 shares in total)
	for playersIndex =1; playersIndex < NumPlayer+1; playersIndex++  {
			var listForAdd []ed.Scalar
			listForAdd = append(listForAdd, secret)
			var i uint32
			for i = 0; i < threshold-1; i++ { //suppose i is the power_index of `player_index`
				var powIndex = ExpScalars(ToScalar(playersIndex), ToScalar(i+1)) // player_index^i
				val := MulScalars(powIndex, coefficients[i])
				listForAdd = append(listForAdd, val)
			}
			value := ed.AddScalars(listForAdd)

			share := Share {
				playersIndex,
				index,
				value,
			}
		if playersIndex != index {
			VecShare = append(VecShare, share)
		} else {
			ShareSaving = share
		}
	}
	pkg := PkgCommitment{
		Index:       index,
		Nounce_R:    nonceCommitment,
		Nounce_u:    u,
		PCommitment: Commitment,
	}

	return pkg, VecShare, ShareSaving
}

// Player verifies all commitments they receive, and return invalid player index and valid commitments
func VerifyPkg(pkg []PkgCommitment, str string) ([]uint32, []PublicCommitment ) {
	var InvalidList []uint32
	var ValidCommitment []PublicCommitment
	//check each one
	for _, p := range pkg {
		if isValid(p,str) {
			ValidCommitment = append(ValidCommitment, p.PCommitment)
		} else {
			InvalidList = append(InvalidList, p.Index)
		}
	}
	return InvalidList, ValidCommitment
}

func DistributeShares(sender, receiver uint32, shares []Share) Share {
	for _, s := range shares {
		if sender != s.Sender {
			fmt.Printf("Sender %d differs from sender %d, in shares", sender, s.Sender)
			panic("DistributeShares")
		}
	}
	for _, s := range shares {
		if receiver == s.Receiver {
			return s
		}
	}
	fmt.Printf("Didn't find corresponding share for %d in sender %d's shares\n", receiver, sender)
	panic("DistributeShares")
}
//player 1 should have share f_2(1), f_3(1)..., f_n(1)
func ReceiveAndGenKey(receiver uint32, ShareSaving Share,
	AllCommitment []PublicCommitment, Shares []Share) (Keys, PublicKeys) {
	//checking length
	if !VerifyShare(ShareSaving, AllCommitment) {
		panic("Fail to verify")
	}
	for _, s := range Shares {
		if !VerifyShare(s,  AllCommitment) {
			panic("Fail to verify")
		}
	}
	var AddScalarList []ed.Scalar
	AddScalarList = append(AddScalarList, ShareSaving.Value)
	for _, s := range Shares {
		AddScalarList = append(AddScalarList, s.Value)
	}
	secret := ed.AddScalars(AddScalarList)

	var AddElementList []ed.Element
	for _, c := range AllCommitment { //don't care about order
		AddElementList = append(AddElementList, c.Commitment[0])
	}
	groupPK := ed.AddElements(AddElementList)

	PK := ed.ScalarMultiplyBase(secret)

	keys := Keys{receiver, secret,PK,groupPK}
	p_keys := PublicKeys{receiver,PK,groupPK}
	return keys, p_keys
}