package frost_test

import (
	"fmt"
	"github/zbh888/FROSTsignature/frost"
	"testing"
)

//Simple test to see if things working
func Test1_Simple(t *testing.T) {
	pkg1, shares1, save1, _ := frost.KeyGen_send(1, 2, 3, "123")
	pkg2, shares2, save2, _ := frost.KeyGen_send(2, 2, 3, "123")
	pkg3, shares3, save3, _ := frost.KeyGen_send(3, 2, 3, "123")
	pkgs := []frost.PkgCommitment{pkg1, pkg2, pkg3}
	//Every one could check it
	u, _ := frost.VerifyPkg(pkgs, "123")
	//They just kept the commitment
	AllCommitment := []frost.PublicCommitment{pkg1.PCommitment, pkg2.PCommitment, pkg3.PCommitment}
	if len(u) != 0 {
		t.Error("No")
	}
	//Simulating sending shares
	shares_to1 := []frost.Share{
		frost.DistributeShares(2, 1, shares2),
		frost.DistributeShares(3, 1, shares3),
	}
	shares_to2 := []frost.Share{
		frost.DistributeShares(1, 2, shares1),
		frost.DistributeShares(3, 2, shares3),
	}
	shares_to3 := []frost.Share{
		frost.DistributeShares(1, 3, shares1),
		frost.DistributeShares(2, 3, shares2),
	}
	//generate keys without panic
	Sk1, Pk1 := frost.ReceiveAndGenKey(1, save1, AllCommitment, shares_to1)
	Sk2, Pk2 := frost.ReceiveAndGenKey(2, save2, AllCommitment, shares_to2)
	_, _ = frost.ReceiveAndGenKey(2, save2, AllCommitment, shares_to2)
	_, _ = frost.ReceiveAndGenKey(3, save3, AllCommitment, shares_to3)
	//Say we sign 2 messages
	ListNonceCommits1, Save1 := frost.PreProcess(1, 2)
	ListNonceCommits2, Save2 := frost.PreProcess(2, 2)
	_, _ = frost.PreProcess(3, 2)
	//Choose SA, S = {1, 2}
	//Server returns the Available nonce commitments
	S := []uint32{1, 2}
	AllNonceCommitments := []frost.PairOfNonceCommitments{
		ListNonceCommits1.List[len(ListNonceCommits1.List)-1],
		ListNonceCommits2.List[len(ListNonceCommits2.List)-1],
	}
	B, message := frost.SA_GenerateB(S, "Awesome", AllNonceCommitments)
	if message != "Awesome" {
		t.Error("Not matching Awesome")
	}

	response1 := frost.Sign(1, "Awesome", B, &Save1, Sk1)
	response2 := frost.Sign(2, "Awesome", B, &Save2, Sk2)

	//GroupPublic
	GroupPublicKey := Sk1.GroupPublicKey

	Signature, InvalidUsers := frost.SA_GenerateSignature(GroupPublicKey, "Awesome", B,
		[]frost.Response{response1, response2},
		[]frost.PublicKeys{Pk1, Pk2},
	)
	fmt.Println(InvalidUsers)

	res := frost.Verify(Signature, GroupPublicKey, "Awesome")
	if res != "Success to verify" {
		t.Error("Fail to verify")
	}
}

func Test2_EdgeErrorHandle(t *testing.T) {
	// threshold is 0
	_, _, _, err := frost.KeyGen_send(1, 0, 3, "123")
	if err == nil { //without error
		t.Error("Fail to throw exception for 0 threshold")
	} else {
		fmt.Println(err)
	}
	_, _, _, err2 := frost.KeyGen_send(2, 1, 0, "123")
	if err2 == nil { //without error
		t.Error("Fail to throw exception for 0 Numplayer")
	} else {
		fmt.Println(err2)
	}
	_, _, _, err3 := frost.KeyGen_send(3, 2, 1, "123")
	if err3 == nil { //without error
		t.Error("Fail to throw exception for threshold > Numplayer")
	} else {
		fmt.Println(err3)
	}
	_, _, _, err4 := frost.KeyGen_send(0, 2, 3, "123")
	_, _, _, err5 := frost.KeyGen_send(4, 2, 3, "123")
	if err4 == nil && err5 == nil { //without error
		t.Error("Fail to throw exception for index error")
	} else {
		fmt.Println("index should > 0 and < numplayers")
	}
}

//Single player signature
func Test3_EdgeCaseSignglePlayer(t *testing.T) {
	pkg1, _, save1, _ := frost.KeyGen_send(1, 1, 1, "1")
	// public commitments, nonce commitment
	pkgs := []frost.PkgCommitment{pkg1}
	// player verifies the package, and return invalid users list u
	u, _ := frost.VerifyPkg(pkgs, "1")
	if len(u) != 0 {
		t.Error("No!")
	}
	// cut the nonce commitment
	AllCommitment := []frost.PublicCommitment{pkg1.PCommitment}
	Sk1, Pk1 := frost.ReceiveAndGenKey(1, save1, AllCommitment, nil)
	ListNonceCommits1, Save1 := frost.PreProcess(1, 2) // 2 signings

	S := []uint32{1}
	AllNonceCommitments := []frost.PairOfNonceCommitments{
		ListNonceCommits1.List[len(ListNonceCommits1.List)-1],
	}
	B, _ := frost.SA_GenerateB(S, "Awesome", AllNonceCommitments)

	response1 := frost.Sign(1, "Awesome", B, &Save1, Sk1)
	//GroupPublic
	GroupPublicKey := Sk1.GroupPublicKey

	Signature, InvalidUsers := frost.SA_GenerateSignature(GroupPublicKey, "Awesome", B,
		[]frost.Response{response1},
		[]frost.PublicKeys{Pk1},
	)
	fmt.Println(InvalidUsers)

	res := frost.Verify(Signature, GroupPublicKey, "Awesome")
	if res != "Success to verify" {
		t.Error("Fail to verify")
	}

}

func Test3_EdgeErrorHandle(t *testing.T) {
}
