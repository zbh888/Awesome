package frost

import ed "gitlab.com/polychainlabs/threshold-ed25519/pkg"

//Commitment should have a size of t
type PublicCommitment struct {
	Commitment []ed.Element
	Index      uint32
}

//For simplicity value of a share is f_sender(receiver)
type Share struct {
	Receiver       uint32
	Sender         uint32
	Value          ed.Scalar
}

type PkgCommitment struct {
	Index      uint32
	Nounce_R   ed.Element
	Nounce_u   ed.Scalar
	PCommitment PublicCommitment
}

type Keys struct {
	index uint32
	secretKey ed.Scalar
	publicKey ed.Element
	groupPublicKey ed.Element
}