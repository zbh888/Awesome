package frost_test

import (
	"fmt"
	"github/zbh888/awsome/frost"
	ed "gitlab.com/polychainlabs/threshold-ed25519/pkg"
	"reflect"
	"testing"
)

//Simple test to see if things working
func Test1_Simple(t *testing.T) {
	pkg1, shares1 , save1 := frost.KeyGen_send(1, 2, 3, "123")
	pkg2, shares2 , save2 := frost.KeyGen_send(2, 2, 3, "123")
	pkg3, shares3 , save3 := frost.KeyGen_send(3, 2, 3, "123")

	pkgs := []frost.PkgCommitment{pkg1,pkg2,pkg3}
	//Every one could check it
	u,_ := frost.VerifyPkg(pkgs, "123")
	//They just kept the commitment
	AllCommitment := []frost.PublicCommitment{pkg1.PCommitment, pkg2.PCommitment, pkg3.PCommitment}
	if len(u)!=0 {t.Error("No")}
	//Simulating sending shares
	shares_to1 := []frost.Share{
		frost.DistributeShares(2,1, shares2),
		frost.DistributeShares(3,1, shares3),
	}
	shares_to2 := []frost.Share{
		frost.DistributeShares(1,2, shares1),
		frost.DistributeShares(3,2, shares3),
	}
	shares_to3 := []frost.Share{
		frost.DistributeShares(1,3, shares1),
		frost.DistributeShares(2,3, shares2),
	}
	//generate keys without panic
	Sk1, Pk1 := frost.ReceiveAndGenKey(1,save1,AllCommitment,shares_to1)
	Sk2, Pk2 := frost.ReceiveAndGenKey(2,save2,AllCommitment,shares_to2)
	_, _ = frost.ReceiveAndGenKey(2,save2,AllCommitment,shares_to2)
	_, _= frost.ReceiveAndGenKey(3,save3,AllCommitment,shares_to3)
	//Say we sign 2 messages
	ListNonceCommits1, Save1 := frost.PreProcess(1,2)
	ListNonceCommits2, Save2 := frost.PreProcess(2,2)
	_, _= frost.PreProcess(3,2)
	//Choose SA, S = {1, 2}
	//Server returns the Available nonce commitments
	S := []uint32{1,2}
	AllNonceCommitments := []frost.PairOfNonceCommitments{
		ListNonceCommits1.List[len(ListNonceCommits1.List)-1],
		ListNonceCommits2.List[len(ListNonceCommits2.List)-1],
	}
	B, message := frost.SA_GenerateB(S, "Awesome",AllNonceCommitments)
	if message!="Awesome" {t.Error("Not matching Awesome")}

	response1 := frost.Sign(1,"Awesome", B, &Save1, Sk1)
	response2 := frost.Sign(2,"Awesome", B, &Save2, Sk2)

	//GroupPublic
	GroupPublicKey := Sk1.GroupPublicKey

	Signature, InvalidUsers :=frost.SA_GenerateSignature(GroupPublicKey,"Awesome",B,
		[]frost.Response{response1,response2},
		[]frost.PublicKeys{Pk1, Pk2},
		)
	fmt.Println(InvalidUsers)

	Challenge := frost.SignGenChallenge(Signature.R, GroupPublicKey, "Awesome")
	R_test := ed.AddElements([]ed.Element{ed.ScalarMultiplyBase(Signature.Z),
		frost.ScMulElement(frost.ScalarNeg(Challenge), GroupPublicKey)})
	if !reflect.DeepEqual(R_test, Signature.R) {
		t.Error("Fail to verify")
	}
}
