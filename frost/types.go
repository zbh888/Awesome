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
//We only need this as the final keys
type Keys struct {
	index uint32
	secretKey ed.Scalar
	publicKey ed.Element
	groupPublicKey ed.Element
}

// Here with processing type

//
type PairOfNonceCommitments struct {
	Nonce_D ed.Element
	Nonce_E ed.Element
}
//This is for storage
type TwoPairOfNonceCommitmentAndNonce struct {
	Nounce_d ed.Scalar
	NounceCommit_D ed.Element
	Nonce_e ed.Scalar
	NonceCommit_E ed.Element
}

//This is for public use
type PairOfNonceCommitmentsList struct {
	index uint32
	List []PairOfNonceCommitments
}

