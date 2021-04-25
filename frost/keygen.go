package frost

import (
	"errors"
	"fmt"
	ed "gitlab.com/polychainlabs/threshold-ed25519/pkg"
)

func KeyGen_send(index, threshold, NumPlayer uint32, str string) (PkgCommitment, []Share, Share, error) {
	if threshold < 1 {
		return PkgCommitment{},nil, Share{}, errors.New("threshold should be at least one")
	}
	if NumPlayer < 1 {
		return PkgCommitment{},nil, Share{}, errors.New("the number of total participants should be at least one")
	}
	if threshold > NumPlayer {
		return PkgCommitment{},nil, Share{}, errors.New("threshold should be smaller than or equal to the number of total participants")
	}
	if index < 1 || index > NumPlayer {
		return PkgCommitment{},nil, Share{}, errors.New("invalid player index")
	}
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

	return pkg, VecShare, ShareSaving, nil
}

// Player verifies all commitments they receive, and return invalid player index and valid commitments
func VerifyPkg(pkg []PkgCommitment, str string) ([]uint32, []PublicCommitment) {
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

func DistributeShares(sender, receiver uint32, shares []Share) (Share,error) {
	if sender == receiver {
		return Share{},  fmt.Errorf("sender should differ from receiver")
	}
	find := false
	for _, s := range shares {
		if sender != s.Sender {
			return Share{},  fmt.Errorf("sender %d differs from index-%d in shares", sender, s.Sender)
		}
		if receiver == s.Receiver {
			if !find {
				find = true
			} else {
				return Share{},  fmt.Errorf("duplicate share for receiver %d found", s.Receiver)
			}
		}
	}
	for _, s := range shares {
		if receiver == s.Receiver {
			return s, nil
		}
	}
	return Share{},  fmt.Errorf("Didn't find corresponding share for index %d in sender %d's shares\n", receiver, sender)
}
//player 1 should have share f_2(1), f_3(1)..., f_n(1)
func ReceiveAndGenKey(receiver uint32, ShareSaving Share,
	AllCommitment []PublicCommitment, Shares []Share) (Keys, PublicKeys, error) {
	Total_Share := append(Shares, ShareSaving)
	//checking length
	for _, s := range Total_Share {
		if s.Receiver != receiver {
			return Keys{}, PublicKeys{}, errors.New("receiver and share owner did not match")
		}
	}
	count := 0
	for _, s := range Total_Share {
		if !VerifyShare(s,  AllCommitment) {
			count += 1
		}
	}
	if count != 0 { // verify in constant time
		return Keys{}, PublicKeys{}, errors.New("fail to verify")
	}
	var AddScalarList []ed.Scalar
	for _, s := range Total_Share {
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
	return keys, p_keys, nil
}