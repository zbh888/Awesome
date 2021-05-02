package frost

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	FiloEd "filippo.io/edwards25519"
	"fmt"
	"gitlab.com/polychainlabs/edwards25519"
	ed "gitlab.com/polychainlabs/threshold-ed25519/pkg"
	"math/big"
)

// This generate a chanllenge
func GenChallenge(index uint32, str string, secretCommitment ed.Element, nounceCommitment ed.Element) ed.Scalar {
	var res []byte
	res = append(ToScalar(index), []byte(str)...)
	res = append(res, secretCommitment...)
	res = append(res, nounceCommitment...)
	sum := sha256.Sum256(res)
	big_num := BytesToBig(sum[:])
	big_num.Mod(big_num, orderL)
	res = Reverse(big_num.Bytes())
	return res
}

func isValid(pkg PkgCommitment, str string) bool {
	if pkg.Index == pkg.PCommitment.Index {
		sender := pkg.Index
		secretCommitment := pkg.PCommitment.Commitment[0]
		nonceCommitment := pkg.Nounce_R
		challenge := GenChallenge(sender, str, secretCommitment, nonceCommitment)
		negChallenge := ScalarNeg(challenge)
		var AddList []ed.Element
		AddList = append(AddList, ed.ScalarMultiplyBase(pkg.Nounce_u))
		AddList = append(AddList, ScMulElement(negChallenge, secretCommitment))
		Rtest := ed.AddElements(AddList)
		if subtle.ConstantTimeCompare(Rtest, nonceCommitment) == 1 {
			return true
		}
	} else {
		panic("Unexpected")
	}
	return false
}

func VerifyShare(share Share, AllCommitment []PublicCommitment) bool {
	sender := share.Sender
	verifier := share.Receiver
	shareCommitment := ed.ScalarMultiplyBase(share.Value)
	var pCommitment []ed.Element
	find := false
	for _, s := range AllCommitment { //We might consider sorting them first
		if s.Index == sender {
			pCommitment = s.Commitment
			find = true
		}
	}
	if !find {
		return false
	}
	t := len(pCommitment) - 1
	res := pCommitment[t]
	for t > 0 {
		res = ScMulElement(ToScalar(verifier), res)
		var AddList []ed.Element
		AddList = append(AddList, res)
		AddList = append(AddList, pCommitment[t-1])
		res = ed.AddElements(AddList)
		t--
	}
	if subtle.ConstantTimeCompare(shareCommitment, res) == 1 {
		return true
	}
	return false
}

// This generate a random scalar
func RandomGenerator() ed.Scalar {
	res, err := rand.Int(rand.Reader, orderL)
	if err != nil {
		println("ERROR : Fail to generate random big int")
	}
	out := make(ed.Scalar, 32)
	copy(out, Reverse(res.Bytes()))
	return out
}

// this convert uint32 to scalar
func ToScalar(index uint32) ed.Scalar {
	out := make(ed.Scalar, 32)
	num := big.NewInt(int64(index)).Bytes()
	copy(out, Reverse(num))
	return out
}

//scalar^pow mod orderL
func ExpScalars(scalar ed.Scalar, pow ed.Scalar) ed.Scalar {
	var result big.Int
	result.Exp(BytesToBig(scalar), BytesToBig(pow), orderL)
	out := make(ed.Scalar, 32)
	copy(out, Reverse(result.Bytes()))
	return out
}

//scalar1 * scalar2 mod orderL
func MulScalars(scalar1 ed.Scalar, scalar2 ed.Scalar) ed.Scalar {
	var result big.Int
	result.Mul(BytesToBig(scalar1), BytesToBig(scalar2))
	result.Mod(&result, orderL)
	out := make(ed.Scalar, 32)
	copy(out, Reverse(result.Bytes()))
	return out
}

//scalar1 + scalar2 mod orderL
func AddScalars(scalar1 ed.Scalar, scalar2 ed.Scalar) ed.Scalar {
	var result big.Int
	result.Add(BytesToBig(scalar1), BytesToBig(scalar2))
	result.Mod(&result, orderL)
	out := make(ed.Scalar, 32)
	copy(out, Reverse(result.Bytes()))
	return out
}

//element ^ scalarE
func ScMulElement(scalarE ed.Scalar, E ed.Element) ed.Element {
	var reduced [32]byte
	var orig [64]byte
	copy(orig[:], scalarE)
	edwards25519.ScReduce(&reduced, &orig)

	var ge edwards25519.ExtendedGroupElement
	var publicKeyBytesE [32]byte
	copy(publicKeyBytesE[:], E)
	ge.FromBytes(&publicKeyBytesE) //converts element to ExtendedGroupElement

	var A edwards25519.ExtendedGroupElement
	ScalarMult(&A, &reduced, &ge) //reference implementation

	var publicKeyBytes [32]byte
	A.ToBytes(&publicKeyBytes)

	element := make(ed.Element, 32)
	copy(element, publicKeyBytes[:])
	return element
}
func ScalarNeg(s ed.Scalar) ed.Scalar {
	z := BytesToBig(s)
	z.Neg(z)
	z.Mod(z, orderL)
	return Reverse(z.Bytes())

}

// used filippo.io/edwards25519
func ScInverse(scalar ed.Scalar) ed.Scalar {
	s := new(FiloEd.Scalar)
	ss, err := s.SetCanonicalBytes(scalar)
	if ss == nil {
		fmt.Println(err)
		panic("Fail to set canonical byte")
	}
	ss = s.Invert(ss)
	return ss.Bytes()
}

func IsInG(element ed.Element) bool {
	var ge edwards25519.ExtendedGroupElement
	var publicKeyBytesE [32]byte
	copy(publicKeyBytesE[:], element)
	return ge.FromBytes(&publicKeyBytesE)
}

func SignGenRoh(index uint32, message string, B []PairOfNonceCommitments) ed.Scalar {
	var res []byte
	res = append(ToScalar(index), []byte(message)...)
	for _, pair := range B {
		res = append(res, pair.Nonce_D...)
		res = append(res, pair.Nonce_E...)
	}
	res = append(res, []byte("nonce")...) //??? Distinguish from H1?
	sum := sha256.Sum256(res)
	big_num := BytesToBig(sum[:])
	big_num.Mod(big_num, orderL)
	res = Reverse(big_num.Bytes())
	return res
}

func SignGenLagrangeCoefficient(signer uint32, S []uint32) ed.Scalar {
	nominator := ToScalar(uint32(1))
	denominator := ToScalar(uint32(1))
	for _, s := range S {
		if s != signer {
			nominator = MulScalars(nominator, ToScalar(s))
			denominator = MulScalars(denominator, AddScalars(ToScalar(s), ScalarNeg(ToScalar(signer))))
		}
	}
	return MulScalars(nominator, ScInverse(denominator)) //Inverse will panic if denominator is 0
}

func SignGenChallenge(R ed.Element, Y ed.Element, message string) ed.Scalar {
	var res []byte
	res = append(R, Y...)
	res = append(res, []byte(message)...)
	sum := sha256.Sum256(res)
	big_num := BytesToBig(sum[:])
	big_num.Mod(big_num, orderL)
	res = Reverse(big_num.Bytes())
	return res
}

func ConstantTimeContains(list []uint32, target uint32) bool {
	flag := false
	for _, x := range list {
		if target == x {
			flag = true
		}
	}
	return flag
}
