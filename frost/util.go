package frost

import (
	"crypto/rand"
	"crypto/sha256"
	ed "gitlab.com/polychainlabs/threshold-ed25519/pkg"
	"math/big"
)
func RandomGenerator() ed.Scalar {
	max := new(big.Int)
	max.Exp(big.NewInt(2), big.NewInt(255), nil).Sub(max, big.NewInt(19))
	res, err := rand.Int(rand.Reader, max)
	if err != nil {
		println("ERROR : Fail to generate random big int")
	}
	res.Mod(res, orderL)
	out := make(ed.Scalar, 32)
	copy(out, Reverse(res.Bytes()))
	return out
}

func GenChallenge(index uint32, str string, secretCommitment ed.Element, nounceCommitment ed.Element) ed.Scalar {
	var res []byte
	res = append(toScalar(index), []byte(str)...)
	res = append(res, secretCommitment...)
	res = append(res, nounceCommitment...)
	sum := sha256.Sum256(res)
	big_num := BytesToBig(sum[:])
	big_num.Mod(big_num, orderL)
	res = Reverse(big_num.Bytes())
	return res
}

// this convert uint32 to scalar
func toScalar(index uint32) ed.Scalar {
	out := make(ed.Scalar, 32)
	num := big.NewInt(int64(index)).Bytes()
	copy(out, Reverse(num))
	return out
}

func ExpScalars(scalar ed.Scalar, pow ed.Scalar) ed.Scalar {
	var result big.Int
	result.Exp(BytesToBig(scalar), BytesToBig(pow), orderL)
	out := make(ed.Scalar, 32)
	copy(out, Reverse(result.Bytes()))
	return out
}

func MulScalars(scalar1 ed.Scalar, scalar2 ed.Scalar) ed.Scalar {
	var result big.Int
	result.Mul(BytesToBig(scalar1), BytesToBig(scalar2))
	result.Mod(&result, orderL)
	out := make(ed.Scalar, 32)
	copy(out, Reverse(result.Bytes()))
	return out
}

func AddScalars(scalar1 ed.Scalar, scalar2 ed.Scalar) ed.Scalar {
	var result big.Int
	result.Add(BytesToBig(scalar1), BytesToBig(scalar2))
	result.Mod(&result, orderL)
	out := make(ed.Scalar, 32)
	copy(out, Reverse(result.Bytes()))
	return out
}


//Reference

//Source : https://gitlab.com/polychainlabs/threshold-ed25519
func Reverse(src []byte) []byte {
	dst := make([]byte, len(src))
	copy(dst, src)
	for i := len(dst)/2 - 1; i >= 0; i-- {
		opp := len(dst) - 1 - i
		dst[i], dst[opp] = dst[opp], dst[i]
	}

	return dst
}

func BytesToBig(bytes []byte) *big.Int {
	var result big.Int
	result.SetBytes(Reverse(bytes))
	return &result
}

var orderL = new(big.Int).SetBits([]big.Word{0x5812631a5cf5d3ed, 0x14def9dea2f79cd6, 0, 0x1000000000000000})
