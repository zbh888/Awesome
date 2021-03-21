package frost

import (
	"crypto/rand"
	"crypto/sha256"
	"gitlab.com/polychainlabs/edwards25519"
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

func ScMulElement(scalarE ed.Scalar, E ed.Element) ed.Element {
	var reduced [32]byte
	var orig [64]byte
	copy(orig[:], scalarE)
	edwards25519.ScReduce(&reduced, &orig)

	var A edwards25519.ExtendedGroupElement
	var ge edwards25519.ExtendedGroupElement

	var publicKeyBytesE [32]byte
	copy(publicKeyBytesE[:], E)
	ge.FromBytes(&publicKeyBytesE)
	ScalarMult(&A, &reduced, &ge)

	var publicKeyBytes [32]byte
	A.ToBytes(&publicKeyBytes)

	element := make(ed.Element, 32)
	copy(element, publicKeyBytes[:])
	return element
}