package frost

import (
	"crypto/rand"
	"crypto/sha256"
	"gitlab.com/polychainlabs/edwards25519"
	ed "gitlab.com/polychainlabs/threshold-ed25519/pkg"
	"math/big"
	"reflect"
)
// This generate a chanllenge
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

func VerifyShare(share Share, receiver uint32, AllCommitment []PublicCommitment) bool {
	sender := share.Sender
	verifier := share.Receiver
	shareCommitment := ed.ScalarMultiplyBase(share.Value)
	var pCommitment []ed.Element
	for _,s := range AllCommitment { //We might consider sorting them first
		if s.Index == sender {
			pCommitment = s.Commitment
		}
	}
	t := len(pCommitment) - 1
	res :=  pCommitment[t]
	for t > 0 {
		res = ScMulElement(toScalar(verifier), res)
		var AddList []ed.Element
		AddList = append(AddList, res)
		AddList = append(AddList, pCommitment[t-1])
		res = ed.AddElements(AddList)
		t--
	}
	if reflect.DeepEqual(shareCommitment, res) {
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
func toScalar(index uint32) ed.Scalar {
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
//scaler1 + scalar2 mod orderL
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