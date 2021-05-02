package frost

import ed "gitlab.com/polychainlabs/threshold-ed25519/pkg"

/// KeyGen
//Commitment should have a size of t
type PublicCommitment struct {
	Commitment []ed.Element
	Index      uint32
}

//For simplicity value of a share is f_sender(receiver)
type Share struct {
	Receiver uint32
	Sender   uint32
	Value    ed.Scalar
}

type PkgCommitment struct {
	Index       uint32
	Nounce_R    ed.Element
	Nounce_u    ed.Scalar
	PCommitment PublicCommitment
}

//We only need this as the final keys
type Keys struct {
	Index          uint32
	SecretKey      ed.Scalar
	PublicKey      ed.Element
	GroupPublicKey ed.Element
}

type PublicKeys struct {
	Index          uint32
	PublicKey      ed.Element
	GroupPublicKey ed.Element
}

// Here with processing type

type PairOfNonceCommitments struct {
	Index   uint32
	Nonce_D ed.Element
	Nonce_E ed.Element
}

//This is for storage
type TwoPairOfNonceCommitmentAndNonce struct {
	Nounce_d       ed.Scalar
	NounceCommit_D ed.Element
	Nonce_e        ed.Scalar
	NonceCommit_E  ed.Element
}

//This is for public use
type PairOfNonceCommitmentsList struct {
	Index uint32
	List  []PairOfNonceCommitments
}

//Here with sign type
type Response struct {
	index uint32
	value ed.Scalar
}

type Signature struct {
	R ed.Element
	Z ed.Scalar
}
