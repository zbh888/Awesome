package frost

import (
	ed "gitlab.com/polychainlabs/threshold-ed25519/pkg"
)

//return random big int, which 0 <= x <= prime - 1
func generateChallenge() {
}

func KeyGen_send(index, threshold, NumPlayer uint32, str string) (PublicCommitment, []Share) {

	var secret ed.Scalar = RandomGenerator()
	var nounce ed.Scalar = RandomGenerator()
	var nounceCommitment ed.Element = ed.ScalarMultiplyBase(nounce)
	var secretCommitment ed.Element = ed.ScalarMultiplyBase(secret)
	//generate challenge
	challenge := GenChallenge(index, str, secretCommitment,nounceCommitment)
	u := AddScalars(nounce, MulScalars(secret, challenge))

	var VecShare []Share
	var PubCommitment []ed.Element
	var coefficients []ed.Scalar
	var players_index uint32

	// random generating coff
	for players_index=1; players_index < threshold; players_index++  {
		coefficients = append(coefficients, RandomGenerator())
	}

	// create commitment (commitment size would be t)
	PubCommitment = append(PubCommitment, secretCommitment)

	for players_index=0; players_index < threshold -1; players_index++  {
		PubCommitment = append(PubCommitment, ed.ScalarMultiplyBase(coefficients[players_index]))
	}
	Commitment := PublicCommitment {PubCommitment, index}

	// generate share for other players (having t-1 shares in total)
	for players_index=1; players_index < NumPlayer+1; players_index++  {
		if players_index != index {

			var listForAdd []ed.Scalar
			listForAdd = append(listForAdd, secret)
			var i uint32
			for i = 0; i < threshold-1; i++ { //suppose i is the power_index of `player_index`
				var powIndex = ExpScalars(toScalar(players_index), toScalar(i+1)) // player_index^i
				val := MulScalars(powIndex, coefficients[i])
				listForAdd = append(listForAdd, val)
			}
			value := ed.AddScalars(listForAdd)

			share := Share {players_index, index, value}
			VecShare = append(VecShare, share)
		}
	}

	return Commitment, VecShare
}