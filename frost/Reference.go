package frost

import (
	"gitlab.com/polychainlabs/edwards25519"
	"math/big"
)

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

//Source: github.com/agl/ed25519/edwards25519/scalarmult.go

func ScalarMult(out *edwards25519.ExtendedGroupElement, k *[32]byte, p *edwards25519.ExtendedGroupElement) {
	tmpP := *p

	var cach edwards25519.CachedGroupElement
	var comp edwards25519.CompletedGroupElement
	var e edwards25519.ExtendedGroupElement

	out.Zero()

	for _, b := range k {
		for bitNum := uint(8); bitNum > 0; bitNum-- {
			tmpP.ToCached(&cach)
			edwards25519.GeAdd(&comp, out, &cach)

			comp.ToExtended(&e)
			ExtendedGroupElementCMove(out, &e, int32((b>>(8-bitNum))&1))

			tmpP.Double(&comp)
			comp.ToExtended(&tmpP)
		}
	}
}

func ExtendedGroupElementCMove(t, u *edwards25519.ExtendedGroupElement, b int32) {
	edwards25519.FeCMove(&t.X, &u.X, b)
	edwards25519.FeCMove(&t.Y, &u.Y, b)
	edwards25519.FeCMove(&t.Z, &u.Z, b)
	edwards25519.FeCMove(&t.T, &u.T, b)
}
