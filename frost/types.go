package frost

import ed "gitlab.com/polychainlabs/threshold-ed25519/pkg"

type PublicCommitment struct {
	Commitment []ed.Element
	Index      uint32
}

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
