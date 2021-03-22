package frost_test

import (
	"github/zbh888/awsome/frost"
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
	_ = frost.ReceiveAndGenKey(1,save1,AllCommitment,shares_to1)
	_ = frost.ReceiveAndGenKey(2,save2,AllCommitment,shares_to2)
	_ = frost.ReceiveAndGenKey(3,save3,AllCommitment,shares_to3)
	//Say we sign 2 messages
	_,_ = frost.PreProcess(1,2)
	_,_ = frost.PreProcess(2,2)
	_,_ = frost.PreProcess(3,2)

}
