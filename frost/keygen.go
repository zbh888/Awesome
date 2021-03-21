package frost

import (
	ed "gitlab.com/polychainlabs/threshold-ed25519/pkg"
	"reflect"
)

//return random big int, which 0 <= x <= prime - 1
func generateChallenge() {
}

func KeyGen_send(index, threshold, NumPlayer uint32, str string) (PkgCommitment, []Share) {

	var secret ed.Scalar = RandomGenerator()
	var nonce ed.Scalar = RandomGenerator()
	var nonceCommitment ed.Element = ed.ScalarMultiplyBase(nonce)
	var secretCommitment ed.Element = ed.ScalarMultiplyBase(secret)
	//generate challenge
	challenge := GenChallenge(index, str, secretCommitment, nonceCommitment)
	u := AddScalars(nonce, MulScalars(secret, challenge))

	var VecShare []Share
	var PubCommitment []ed.Element
	var coefficients []ed.Scalar
	var playersIndex uint32

	// random generating coff
	for playersIndex =1; playersIndex < threshold; playersIndex++  {
		coefficients = append(coefficients, RandomGenerator())
	}

	// create commitment (commitment size would be t)
	PubCommitment = append(PubCommitment, secretCommitment)

	for playersIndex =0; playersIndex < threshold -1; playersIndex++  {
		PubCommitment = append(PubCommitment, ed.ScalarMultiplyBase(coefficients[playersIndex]))
	}
	Commitment := PublicCommitment {
		PubCommitment,
		index,
	}

	// generate share for other players (having t-1 shares in total)
	for playersIndex =1; playersIndex < NumPlayer+1; playersIndex++  {
		if playersIndex != index {

			var listForAdd []ed.Scalar
			listForAdd = append(listForAdd, secret)
			var i uint32
			for i = 0; i < threshold-1; i++ { //suppose i is the power_index of `player_index`
				var powIndex = ExpScalars(toScalar(playersIndex), toScalar(i+1)) // player_index^i
				val := MulScalars(powIndex, coefficients[i])
				listForAdd = append(listForAdd, val)
			}
			value := ed.AddScalars(listForAdd)

			share := Share {
				playersIndex,
				index,
				value,
			}
			VecShare = append(VecShare, share)
		}
	}
	pkg := PkgCommitment{
		Index:       index,
		Nounce_R:    nonceCommitment,
		Nounce_u:    u,
		PCommitment: Commitment,
	}

	return pkg, VecShare
}
// Player verifies all commitments they receive, and return invalid player index and valid commitments
func VerifyPkg(index uint32, pkg []PkgCommitment, str string) ([]uint32, []PublicCommitment ) {
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

func isValid(pkg PkgCommitment, str string) bool {
	if pkg.Index == pkg.PCommitment.Index {
		sender := pkg.Index
		secretCommitment := pkg.PCommitment.Commitment[0]
		nonceCommitment := pkg.Nounce_R
		challenge := GenChallenge(sender, str, secretCommitment, nonceCommitment)
		z := BytesToBig(challenge)
		z.Neg(z)
		var negChallenge ed.Scalar = Reverse(z.Bytes())

		var AddList []ed.Element
		AddList = append(AddList, ed.ScalarMultiplyBase(pkg.Nounce_u))
		AddList = append(AddList, ScMulElement(negChallenge, secretCommitment))
		Rtest := ed.AddElements(AddList)
		if reflect.DeepEqual(Rtest,nonceCommitment) {
			return true
		}
	}
	return  false
}