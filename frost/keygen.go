package frost

import (
	"crypto/rand"
	ed "gitlab.com/polychainlabs/threshold-ed25519/pkg"
	"math/big"

	//	"gitlab.com/polychainlabs/threshold-ed25519/pkg"
)

var orderL = new(big.Int).SetBits([]big.Word{0x5812631a5cf5d3ed, 0x14def9dea2f79cd6, 0, 0x1000000000000000})

type (
	Scalar  []byte
	Element []byte
)

type PublicCommitment struct {
	commitment []Element
	index      uint32
}

type Share struct {
	receiver       uint32
	sender         uint32
	value          Scalar
}

//return random big int, which 0 <= x <= prime - 1
func RandomGenerator() Scalar {
	max := new(big.Int)
	max.Exp(big.NewInt(2), big.NewInt(255), nil).Sub(max, big.NewInt(19))
	res, err := rand.Int(rand.Reader, max)
	if err != nil {
		println("ERROR : Fail to generate random big int")
	}
	res.Mod(res, orderL)
	out := make(Scalar, 32)
	copy(out, util.Reverse(res.Bytes()))
	return out
}

func generateChallenge() {
}

func KeyGen_send(
	index uint32, threshold uint32, NumPlayer uint32 , str string,
	prime *big.Int, base *big.Int) (PublicCommitment, []Share) {

	var secret *big.Int = RandomGenerator(prime)
	var nounce *big.Int = RandomGenerator(prime)
	//generate challenge

	var VecShare []Share
	var PubCommitment []*big.Int
	var coefficients []*big.Int
	var players_index uint32

	// random generating coff
	for players_index=1; players_index < threshold; players_index++  {
		coefficients = append(coefficients, RandomGenerator(prime))
	}

	// create commitment (commitment size would be t)
	PubCommitment = append(PubCommitment, groupOperation(base, secret, prime))
	for players_index=0; players_index < threshold -1; players_index++  {
		PubCommitment = append(PubCommitment, groupOperation(base, coefficients[players_index], prime))
	}
	Commitment := PublicCommitment {PubCommitment, index}

	// generate share for other players (having t-1 shares in total)
	for players_index=1; players_index < NumPlayer+1; players_index++  {
		if players_index != index {
			var value *big.Int = new(big.Int)  //copy secret for addition
			value.Add(value, secret)

			var i uint32
			for i = 0; i < threshold-1; i++ { //suppose i is the power_index of `player_index`
				var powIndex = groupOperation(big.NewInt(int64(players_index)), big.NewInt(int64(i+1)),prime) // player_index^i
				powIndex.Mul(powIndex, coefficients[i]) // coff(i) * player_index^i
				powIndex.Mod(powIndex, prime) //modulo
				value.Add(value, powIndex) //accumulate on secret
			}

			share := Share {players_index, index, value}
			VecShare = append(VecShare, share)
		}
	}

	return Commitment, VecShare
}