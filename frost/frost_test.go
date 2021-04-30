package frost_test

import (
	"fmt"
	"github/zbh888/FROSTsignature/frost"
	ed "gitlab.com/polychainlabs/threshold-ed25519/pkg"
	"testing"
)

// Test for Key generation

func TestKeyGen1_UsageErrorHandle(t *testing.T) {
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

// Change nonce or commitment will make user get into invalid list.
func TestKeyGen2_FailToVerifyCommitment(t *testing.T) {
	pkg1, _, _, _ := frost.KeyGen_send(1, 2, 4, "123")
	pkg2, _, _, _ := frost.KeyGen_send(2, 2, 4, "123")
	pkg3, _, _, _ := frost.KeyGen_send(3, 2, 4,"Wrong")
	pkg4, _, _, _ := frost.KeyGen_send(4, 2, 4,"123")
	pkg2.Nounce_u = frost.ToScalar(88888888)
	pkg1.Nounce_R = ed.ScalarMultiplyBase(frost.ToScalar(12345678))
	//Change the secret
	pkg4.PCommitment.Commitment[0] = ed.ScalarMultiplyBase(frost.ToScalar(12345678))
	pkgs := []frost.PkgCommitment{pkg1, pkg2, pkg3, pkg4}
	// Assume there is no duplicate issue, and number fits (easily detected duplication by Pkg index)
	invalid, _ := frost.VerifyPkg(pkgs,"123")
	if len(invalid) != 4 {
		t.Error("Commitment should fail but not detected")
	}
	pkg5, _, _, _ := frost.KeyGen_send(5, 2, 5,"123")
	pkgs = []frost.PkgCommitment{pkg1, pkg2, pkg3, pkg4, pkg5}
	// Change this should not affect anything in this case
	pkg5.PCommitment.Commitment[1] = ed.ScalarMultiplyBase(frost.ToScalar(12345678))
	invalid, _ = frost.VerifyPkg(pkgs,"123")
	if len(invalid) != 4 {
		t.Error("Commitment should fail but not detected")
	}
}

func TestKeyGen3_DistributeFailure(t *testing.T) {
	_, shares1, _, _ := frost.KeyGen_send(1, 2, 3, "123")
	// Distribute to non-existing player
	_, err := frost.DistributeShares(1,4,shares1)
	if err != nil {
		fmt.Println(err)
	} else {
		t.Error("Fail when distributing to non-existing player")
	}
	_, err = frost.DistributeShares(1,1,shares1)
	if err != nil {
		fmt.Println(err)
	} else {
		t.Error("Fail when self sending")
	}
	shares1[1].Sender = 2
	_, err = frost.DistributeShares(1,2,shares1)
	if err != nil {
		fmt.Println(err)
	} else {
		t.Error("Fail when shares sender get changed")
	}
	shares1[1].Sender = 1
	shares1[0].Receiver = 3
	_, err = frost.DistributeShares(1,3,shares1)
	if err != nil {
		fmt.Println(err)
	} else {
		t.Error("Fail when shares got duplicate receiver")
	}
}

func TestKeyGen4_ReceiveFailure(t *testing.T) {
	pkg1, shares1, save1, _ := frost.KeyGen_send(1, 2, 3, "123")
	pkg2, shares2, save2, _ := frost.KeyGen_send(2, 2, 3, "123")
	pkg3, shares3, save3, _ := frost.KeyGen_send(3, 2, 3, "123")
	pkgs := []frost.PkgCommitment{pkg1, pkg2, pkg3}
	//Every one could check it, and they just kept the commitment
	u, AllCommitment := frost.VerifyPkg(pkgs, "123")
	if len(u) != 0 {
		t.Error("No")
	}
	//Simulating sending shares
	s1, _ := frost.DistributeShares(2, 1, shares2)
	s2, _ := frost.DistributeShares(3, 1, shares3)
	shares_to1 := []frost.Share{s1,s2}
	s1, _ = frost.DistributeShares(1, 2, shares1)
	s2, _ = frost.DistributeShares(3, 2, shares3)
	shares_to2 := []frost.Share{s1,s2}
	s1, _ = frost.DistributeShares(1, 3, shares1)
	s2, _ = frost.DistributeShares(2, 3, shares2)
	shares_to3 := []frost.Share{s1,s2}
	//generate keys without panic
	_, _, err := frost.ReceiveAndGenKey(2, save1, AllCommitment, shares_to1)
	if err != nil {
		fmt.Println(err)
	} else {
		t.Error("Fail when wrongly indexing")
	}
	save2.Value = frost.ToScalar(88888888)
	_, _, err = frost.ReceiveAndGenKey(2, save2, AllCommitment, shares_to2)
	if err != nil {
		fmt.Println(err)
	} else {
		t.Error("Fail when share get changed")
	}
	shares_to3[0].Value = frost.ToScalar(88888888)
	_, _, err = frost.ReceiveAndGenKey(3, save3, AllCommitment, shares_to3)
	if err != nil {
		fmt.Println(err)
	} else {
		t.Error("Fail when share get changed")
	}
}

// Test for Signing

func TestSign1_preprocess(t *testing.T) {
	_,_,err := frost.PreProcess(1,0)
	if err == nil {
		t.Error("process test fail")
	}
	_, _, err = frost.PreProcess(0,1)
	if err == nil {
		t.Error("process test fail")
	}
}

func TestSign2_GenerateB(t *testing.T) {
	ListNonceCommits1, _, _ := frost.PreProcess(1, 4)
	ListNonceCommits2, _, _ := frost.PreProcess(2, 1)
	ListNonceCommits3, _, _ := frost.PreProcess(3, 10)
	ListNonceCommits4, _, _ := frost.PreProcess(4, 2)
	AllNonceCommitments := []frost.PairOfNonceCommitments{
		ListNonceCommits1.List[len(ListNonceCommits1.List)-1],
		ListNonceCommits2.List[len(ListNonceCommits2.List)-1],
		ListNonceCommits3.List[len(ListNonceCommits2.List)-1],
		ListNonceCommits4.List[len(ListNonceCommits2.List)-1],
	}
	S := []uint32{1, 2, 5, 3, 4}
	B, _, missing := frost.SA_GenerateB(S, "Awesome", AllNonceCommitments)
	if len(missing) != 1 {
		t.Error("Fail")
	}
	if len(B) != 0 {
		t.Error("Fail")
	}

}

func TestSign3_Sign(t *testing.T) {
}

func TestSign4_Aggregation(t *testing.T) {
}

// Test for the whole algorithm

// Single player signature, with magic number
func TestAlog1_EdgeCaseSinglePlayer(t *testing.T) {
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
	Sk1, Pk1, _ := frost.ReceiveAndGenKey(1, save1, AllCommitment, nil)
	ListNonceCommits1, Save1,_ := frost.PreProcess(1, 2) // 2 signings

	S := []uint32{1}
	AllNonceCommitments := []frost.PairOfNonceCommitments{
		ListNonceCommits1.List[len(ListNonceCommits1.List)-1],
	}
	B, _, _ := frost.SA_GenerateB(S, "Awesome", AllNonceCommitments)

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

//Simple test to see if things working
func TestAlog2_Simple(t *testing.T) {
	pkg1, shares1, save1, _ := frost.KeyGen_send(1, 2, 3, "123")
	pkg2, shares2, save2, _ := frost.KeyGen_send(2, 2, 3, "123")
	pkg3, shares3, save3, _ := frost.KeyGen_send(3, 2, 3, "123")
	pkgs := []frost.PkgCommitment{pkg1, pkg2, pkg3}
	//Every one could check it, and they just kept the commitment
	u, AllCommitment := frost.VerifyPkg(pkgs, "123")
	if len(u) != 0 {
		t.Error("No")
	}
	//Simulating sending shares
	s1, _ := frost.DistributeShares(2, 1, shares2)
	s2, _ := frost.DistributeShares(3, 1, shares3)
	shares_to1 := []frost.Share{s1,s2}
	s1, _ = frost.DistributeShares(1, 2, shares1)
	s2, _ = frost.DistributeShares(3, 2, shares3)
	shares_to2 := []frost.Share{s1,s2}
	s1, _ = frost.DistributeShares(1, 3, shares1)
	s2, _ = frost.DistributeShares(2, 3, shares2)
	shares_to3 := []frost.Share{s1,s2}
	//generate keys without panic
	Sk1, Pk1, _ := frost.ReceiveAndGenKey(1, save1, AllCommitment, shares_to1)
	Sk2, Pk2, _ := frost.ReceiveAndGenKey(2, save2, AllCommitment, shares_to2)
	_, _, _ = frost.ReceiveAndGenKey(3, save3, AllCommitment, shares_to3)
	//Say we sign 2 messages
	ListNonceCommits1, Save1, _ := frost.PreProcess(1, 2)
	ListNonceCommits2, Save2, _ := frost.PreProcess(2, 2)
	_, _, _ = frost.PreProcess(3, 2)
	//Choose SA, S = {1, 2}
	//Server returns the Available nonce commitments
	S := []uint32{1, 2}
	AllNonceCommitments := []frost.PairOfNonceCommitments{
		ListNonceCommits1.List[len(ListNonceCommits1.List)-1],
		ListNonceCommits2.List[len(ListNonceCommits2.List)-1],
	}
	B, message, _ := frost.SA_GenerateB(S, "Awesome", AllNonceCommitments)
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

// More Players
// 400 players in total, threshold = 100, S = {1, ... , 150}
func TestAlog3_CompleteMorePlayer(t *testing.T) {
}

// Correctness

func TestAlog4_Correctness(t *testing.T) {
}

func TestAlog5_SLessThanThreshold(t *testing.T) {
}
