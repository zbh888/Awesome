package frost_test

import (
	"fmt"
	"FROSTsignature/frost"
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
	pkg3, _, _, _ := frost.KeyGen_send(3, 2, 4, "Wrong")
	pkg4, _, _, _ := frost.KeyGen_send(4, 2, 4, "123")
	pkg2.Nounce_u = frost.ToScalar(88888888)
	pkg1.Nounce_R = ed.ScalarMultiplyBase(frost.ToScalar(12345678))
	//Change the secret
	pkg4.PCommitment.Commitment[0] = ed.ScalarMultiplyBase(frost.ToScalar(12345678))
	pkgs := []frost.PkgCommitment{pkg1, pkg2, pkg3, pkg4}
	// Assume there is no duplicate issue, and number fits (easily detected duplication by Pkg index)
	invalid, _ := frost.VerifyPkg(pkgs, "123")
	if len(invalid) != 4 {
		t.Error("Commitment should fail but not detected")
	}
	pkg5, _, _, _ := frost.KeyGen_send(5, 2, 5, "123")
	pkgs = []frost.PkgCommitment{pkg1, pkg2, pkg3, pkg4, pkg5}
	// Change this should not affect anything in this case
	pkg5.PCommitment.Commitment[1] = ed.ScalarMultiplyBase(frost.ToScalar(12345678))
	invalid, _ = frost.VerifyPkg(pkgs, "123")
	if len(invalid) != 4 {
		t.Error("Commitment should fail but not detected")
	}
}

func TestKeyGen3_DistributeFailure(t *testing.T) {
	_, shares1, _, _ := frost.KeyGen_send(1, 2, 3, "123")
	// Distribute to non-existing player
	_, err := frost.DistributeShares(1, 4, shares1)
	if err != nil {
		fmt.Println(err)
	} else {
		t.Error("Fail when distributing to non-existing player")
	}
	_, err = frost.DistributeShares(1, 1, shares1)
	if err != nil {
		fmt.Println(err)
	} else {
		t.Error("Fail when self sending")
	}
	shares1[1].Sender = 2
	_, err = frost.DistributeShares(1, 2, shares1)
	if err != nil {
		fmt.Println(err)
	} else {
		t.Error("Fail when shares sender get changed")
	}
	shares1[1].Sender = 1
	shares1[0].Receiver = 3
	_, err = frost.DistributeShares(1, 3, shares1)
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
	shares_to1 := []frost.Share{s1, s2}
	s1, _ = frost.DistributeShares(1, 2, shares1)
	s2, _ = frost.DistributeShares(3, 2, shares3)
	shares_to2 := []frost.Share{s1, s2}
	s1, _ = frost.DistributeShares(1, 3, shares1)
	s2, _ = frost.DistributeShares(2, 3, shares2)
	shares_to3 := []frost.Share{s1, s2}
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
	_, _, err := frost.PreProcess(1, 0)
	if err == nil {
		t.Error("process test fail")
	}
	_, _, err = frost.PreProcess(0, 1)
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
	pkg1, shares1, save1, _ := frost.KeyGen_send(1, 2, 3, "123")
	pkg2, shares2, save2, _ := frost.KeyGen_send(2, 2, 3, "123")
	pkg3, shares3, save3, _ := frost.KeyGen_send(3, 2, 3, "123")
	pkgs := []frost.PkgCommitment{pkg1, pkg2, pkg3}
	u, AllCommitment := frost.VerifyPkg(pkgs, "123")
	if len(u) != 0 {
		t.Error("No")
	}
	s1, _ := frost.DistributeShares(2, 1, shares2)
	s2, _ := frost.DistributeShares(3, 1, shares3)
	shares_to1 := []frost.Share{s1, s2}
	s1, _ = frost.DistributeShares(1, 2, shares1)
	s2, _ = frost.DistributeShares(3, 2, shares3)
	shares_to2 := []frost.Share{s1, s2}
	s1, _ = frost.DistributeShares(1, 3, shares1)
	s2, _ = frost.DistributeShares(2, 3, shares2)
	shares_to3 := []frost.Share{s1, s2}
	Sk1, _, _ := frost.ReceiveAndGenKey(1, save1, AllCommitment, shares_to1)
	Sk2, _, _ := frost.ReceiveAndGenKey(2, save2, AllCommitment, shares_to2)
	_, _, _ = frost.ReceiveAndGenKey(3, save3, AllCommitment, shares_to3)
	//Say we sign 2 messages
	ListNonceCommits1, Save1, _ := frost.PreProcess(1, 5)
	ListNonceCommits2, Save2, _ := frost.PreProcess(2, 5)
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
	//zero length
	var ZeroLengthSave []frost.TwoPairOfNonceCommitmentAndNonce
	_, err := frost.Sign(1, "Awesome", B, &ZeroLengthSave, Sk1)
	if err == nil {
		t.Error("zero length fail")
	}
	//save should be deleted automatically
	_, err = frost.Sign(2, "Awesome", B, &Save1, Sk1)
	if err == nil {
		t.Error("key matching fail")
	}
	_, _ = frost.Sign(1, "Awesome", B, &Save1, Sk1)
	if len(Save1) != 4 {
		t.Error("zero length fail")
	}
	//Commitment is not in the field
	temp := B[0].Nonce_D
	B[0].Nonce_D = []byte("randomdafezsda")
	_, err = frost.Sign(2, "Awesome", B, &Save2, Sk2)
	if err == nil {
		t.Error("Checking in filed fail")
	}
	B[0].Nonce_D = temp
	B[0].Nonce_E = []byte("randomdafezsda")
	_, err = frost.Sign(2, "Awesome", B, &Save2, Sk2)
	if err == nil {
		t.Error("Checking in filed fail")
	}
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
	ListNonceCommits1, Save1, _ := frost.PreProcess(1, 2) // 2 signings

	S := []uint32{1}
	AllNonceCommitments := []frost.PairOfNonceCommitments{
		ListNonceCommits1.List[len(ListNonceCommits1.List)-1],
	}
	B, _, _ := frost.SA_GenerateB(S, "Awesome", AllNonceCommitments)

	response1, _ := frost.Sign(1, "Awesome", B, &Save1, Sk1)
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
	shares_to1 := []frost.Share{s1, s2}
	s1, _ = frost.DistributeShares(1, 2, shares1)
	s2, _ = frost.DistributeShares(3, 2, shares3)
	shares_to2 := []frost.Share{s1, s2}
	s1, _ = frost.DistributeShares(1, 3, shares1)
	s2, _ = frost.DistributeShares(2, 3, shares2)
	shares_to3 := []frost.Share{s1, s2}
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

	response1, _ := frost.Sign(1, "Awesome", B, &Save1, Sk1)
	response2, _ := frost.Sign(2, "Awesome", B, &Save2, Sk2)

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
// 80 players in total, threshold = 30, S = {1, 3, 5, ... , 79}, test takes about 80 seconds
// This test simulate the procedure by putting all stuff in array, but in real life, users are independent
func TestAlog3_CompleteMorePlayer(t *testing.T) {
	TotalNumPlayer := uint32(80)
	ChosenNumPlayer := uint32(40)
	threshold := uint32(30)
	iterator := uint32(1)
	NumOfSigning := 2                              // Preprocess # of signing
	message := "Transfer 100$ to 255:255:255:255." // This is the message
	/*  Round 1 - start
	================================================ */
	var PkgCommitmentList []frost.PkgCommitment // commitments of secret
	var ShareList [][]frost.Share               // shares wait to be distribute
	var SaveShareList []frost.Share             // share of their own index
	for iterator <= TotalNumPlayer {
		pkg, shares, save, err := frost.KeyGen_send(iterator, threshold, TotalNumPlayer, "DetailTest")
		if err != nil {
			t.Error("Keygen fail")
		}
		PkgCommitmentList = append(PkgCommitmentList, pkg)
		ShareList = append(ShareList, shares)
		SaveShareList = append(SaveShareList, save)
		iterator++
	}
	iterator = uint32(1)

	// Verification of the commitment
	// Verification success, then each player deletes stuff about zero knowledge and only keeps variable Allcommitment,
	InvalidUserList, AllCommitment := frost.VerifyPkg(PkgCommitmentList, "DetailTest")
	if len(InvalidUserList) != 0 {
		t.Error("Verification fail")
	}
	/*  Round 1 - end
	================================================ */
	/*  Round 2 - start
	================================================ */
	var SharesToPlayerList [][]frost.Share
	// each player receive shares
	for iterator <= TotalNumPlayer {
		j := uint32(0)
		var shareToPlayer []frost.Share
		for j < TotalNumPlayer {
			// other players send shares to this player
			if j+1 != iterator {
				// distribute share
				s, err := frost.DistributeShares(j+1, iterator, ShareList[j])
				if err != nil {
					t.Error("Fail to distribute")
				}
				shareToPlayer = append(shareToPlayer, s)
			}
			j++
		}
		SharesToPlayerList = append(SharesToPlayerList, shareToPlayer)
		iterator++
	}
	iterator = uint32(1)
	// Then generate the keys
	var SecretKeyList []frost.Keys
	var PublicKeyList []frost.PublicKeys
	for iterator <= TotalNumPlayer {
		SK, PK, err := frost.ReceiveAndGenKey(iterator, SaveShareList[iterator-1], AllCommitment, SharesToPlayerList[iterator-1])
		if err != nil {
			t.Error("Fail to generate key")
		}
		SecretKeyList = append(SecretKeyList, SK)
		PublicKeyList = append(PublicKeyList, PK)
		iterator++
	}
	iterator = uint32(1)
	// Just get the GroupPublicKey here, we can verify the signature using this key.
	GroupPublicKey := PublicKeyList[0].GroupPublicKey
	/*  Round 2 - end
	================================================ */

	/*  Preprocess - start
	================================================ */
	// Pick chosen players, S
	var S []uint32
	for iterator <= ChosenNumPlayer {
		S = append(S, 2*iterator-1)
		iterator++
	}
	iterator = uint32(1)
	// Preprocess
	var NonceCommitmentsList []frost.PairOfNonceCommitmentsList  // This is in public
	var NonceSaveList [][]frost.TwoPairOfNonceCommitmentAndNonce // This is the local save
	for iterator <= TotalNumPlayer {
		ListNonceCommits, Save, err := frost.PreProcess(iterator, NumOfSigning)
		if err != nil {
			t.Error("Process failure")
		}
		NonceCommitmentsList = append(NonceCommitmentsList, ListNonceCommits)
		NonceSaveList = append(NonceSaveList, Save)
		iterator++
	}
	iterator = uint32(1)

	/*  Sign - start
	================================================ */
	// Server Extract the commitments used in this signing
	// Pick the last element in the list, which submitted by the member in S
	// Server could delete them if success, but it depends on server, so omit the delete
	var AllNonceCommitments []frost.PairOfNonceCommitments
	for _, member := range S {
		AllNonceCommitments = append(AllNonceCommitments,
			NonceCommitmentsList[member-1].List[len(NonceCommitmentsList[member-1].List)-1])
	}

	// choose some aggregator, generate B
	B, m, MissingUserList := frost.SA_GenerateB(S, message, AllNonceCommitments)
	if len(MissingUserList) != 0 {
		t.Error("Fail to generate B")
	}
	if m != message {
		t.Error("message returned by aggregator is wrong")
	}

	// Response list of every member in S
	var ResponseList []frost.Response
	var PublicKeyInS []frost.PublicKeys
	for _, member := range S {
		r, err := frost.Sign(member, m, B, &(NonceSaveList[member-1]), SecretKeyList[member-1])
		if err != nil {
			t.Error("fail to sign")
		}
		ResponseList = append(ResponseList, r)
		PublicKeyInS = append(PublicKeyInS, PublicKeyList[member-1])
	}

	// SA generate the response
	Signature, InvalidUsers := frost.SA_GenerateSignature(GroupPublicKey, m, B, ResponseList, PublicKeyInS)
	if len(InvalidUsers) != 0 {
		t.Error("Generate response fail")
	}
	/*  Sign - end
	================================================ */

	// Verification
	res := frost.Verify(Signature, GroupPublicKey, message)
	if res == "Success to verify" {
		if ChosenNumPlayer >= threshold {
		} else {
			t.Error("threshold less than or equal to S should success")
		}
	}
	if res == "Fail to verify" {
		if ChosenNumPlayer < threshold {
		} else {
			t.Error("threshold bigger than S should fail")
		}
	}

}

// If S is less than threshold, the generated signature can't be verified by public key
func TestAlog4_SLessThanThreshold(t *testing.T) {
	pkg1, shares1, save1, _ := frost.KeyGen_send(1, 2, 3, "123")
	pkg2, shares2, save2, _ := frost.KeyGen_send(2, 2, 3, "123")
	pkg3, shares3, save3, _ := frost.KeyGen_send(3, 2, 3, "123")
	pkgs := []frost.PkgCommitment{pkg1, pkg2, pkg3}
	//Every one could check it, and they just kept the commitment
	_, AllCommitment := frost.VerifyPkg(pkgs, "123")
	//Simulating sending shares
	s1, _ := frost.DistributeShares(2, 1, shares2)
	s2, _ := frost.DistributeShares(3, 1, shares3)
	shares_to1 := []frost.Share{s1, s2}
	s1, _ = frost.DistributeShares(1, 2, shares1)
	s2, _ = frost.DistributeShares(3, 2, shares3)
	shares_to2 := []frost.Share{s1, s2}
	s1, _ = frost.DistributeShares(1, 3, shares1)
	s2, _ = frost.DistributeShares(2, 3, shares2)
	shares_to3 := []frost.Share{s1, s2}
	//generate keys without panic
	Sk1, Pk1, _ := frost.ReceiveAndGenKey(1, save1, AllCommitment, shares_to1)
	_, _, _ = frost.ReceiveAndGenKey(2, save2, AllCommitment, shares_to2)
	_, _, _ = frost.ReceiveAndGenKey(3, save3, AllCommitment, shares_to3)
	//Say we sign 2 messages
	ListNonceCommits1, Save1, _ := frost.PreProcess(1, 2)
	_, _, _ = frost.PreProcess(3, 2)
	//Choose SA, S = {1}, which is less than threshold
	//Server returns the Available nonce commitments
	S := []uint32{1}
	AllNonceCommitments := []frost.PairOfNonceCommitments{
		ListNonceCommits1.List[len(ListNonceCommits1.List)-1],
	}
	B, message, _ := frost.SA_GenerateB(S, "Awesome", AllNonceCommitments)
	if message != "Awesome" {
		t.Error("Not matching Awesome")
	}

	response1, _ := frost.Sign(1, "Awesome", B, &Save1, Sk1)
	//GroupPublic
	GroupPublicKey := Sk1.GroupPublicKey

	Signature, InvalidUsers := frost.SA_GenerateSignature(GroupPublicKey, "Awesome", B,
		[]frost.Response{response1},
		[]frost.PublicKeys{Pk1},
	)
	fmt.Println(InvalidUsers)

	res := frost.Verify(Signature, GroupPublicKey, "Awesome")
	if res != "Fail to verify" {
		t.Error("Fail")
	}
}
