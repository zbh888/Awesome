# FROST Implementation

## Usage Description

### Key Generation
Users would have to generate a package of keys first, these four functions help every user to generate his/her individual secret key and public key,
and a group public key using the property of homomorphism of the algorithm.

Note that each user have to send a proof of knowledge first, and send the shares of other players later. So they send and receive something twice.
```go
//KeyGen_send : User with index i build it's own degree-(t-1) polynomial f_i and generate the commitments and shares.
//INPUT:
//              index, (uint32) : The user index, i
//          threshold, (uint32) : The threshold set in the beginning
//          NumPlayer, (uint32) : Total number of players, n
//                str, (string) : A context string to avoid replay attacks
//OUTPUT:
//              (PkgCommitment) : A list of commitments on coefficients along with the proof of knowledge, this variable should be sent first.
//                    ([]Share) : A list of shares f_i(j) for all 1<=j<=n except j=i. This variable should be deleted later.
//                      (Share) : The share f_i(i) kept by the user i
func KeyGen_send(index, threshold, NumPlayer uint32, str string) (PkgCommitment, []Share, Share)

//VerifyPkg : User receive the all PkgCommitments for all users and verify it.
//INPUT:
//       pkg, ([]PkgCommitment) : All PkgCommitments for all users
//                str, (string) : A context string to avoid replay attacks
//OUTPUT:
//                   ([]uint32) : A list of invalid users
//         ([]PublicCommitment) : All PkgCommitments for all users but without nonce commitments
func VerifyPkg(pkg []PkgCommitment, str string) ([]uint32, []PublicCommitment )

//DistributeShares :
//INPUTS:
//             sender, (uint32) :
//           receiver, (uint32) :
//            shares, ([]Share) :
//OUTPUTS:
//                      (Share) :
func DistributeShares(sender, receiver uint32, shares []Share) Share

//ReceiveAndGenKey :
//INPUTS:
//                  receiver, (uint32) :
//                ShareSaving, (Share) :
// AllCommitment, ([]PublicCommitment) :
//                   Shares ([]Shares) :
//OUTPUTS:
//                              (Keys) :
//                        (PublicKeys) :
func ReceiveAndGenKey(receiver uint32, ShareSaving Share, AllCommitment []PublicCommitment, Shares []Share) (Keys, PublicKeys)
```

### Signature Generation

Generate a signature

```go
func PreProcess(index uint32, numSigns int) (PairOfNonceCommitmentsList, []TwoPairOfNonceCommitmentAndNonce)

func SA_GenerateB(S []uint32, message string ,AllCommitments []PairOfNonceCommitments) ([]PairOfNonceCommitments, string)

func Sign(index uint32, message string, B []PairOfNonceCommitments, save *[]TwoPairOfNonceCommitmentAndNonce, keys Keys) Response

func SA_GenerateSignature(Group_PK ed.Element, message string, B []PairOfNonceCommitments, responses []Response, Pks []PublicKeys) (Signature, []uint32)
```

## Changing Logs
I changed some code to enhance the security of my code based on this
#### Source : https://github.com/veorq/cryptocoding

### 1. Time of comparison between bytes vulnerability (Yes)

#### Originally

I used `reflect.DeepEqual(a,b)` to compare points on the curve (32 bytes array)

#### Problem
```go
//Source: https://golang.org/src/reflect/deepequal.go
case Array:
  		for i := 0; i < v1.Len(); i++ {
  			if !deepValueEqual(v1.Index(i), v2.Index(i), visited) {
  				return false
  			}
  		}
```
We can see it didn't use constant time for comparison, so attacker could possibly use this timing information for
different bytes array to learn the correctness of his/her bytes array during the process of forging a signature.

Also note that compilers has freedom to change assembly execution to optimize code, so we should be careful. 

#### Solution:
Use `ConstantTimeCompare(a,b) == 1` to achieve time equality. (from `crypto/subtle`)

### 2. Time of branching on secret data vulnerability (No)

#### Analysis

Consider what are secret data in this protocol? 

##### When `generating keys` : 

The secret coefficient and the secret share should be kept secret. 

In function `VerifyPkg(package)`, attacker could change the content of package. However, it is not a vulnerability since
package contains public commitments and nonce commitment and it verifies in constant time.

In function `ReceiveAndGenKey(shares)`, attacker could change the shares to test the program, if they succeed, secret share would be exposed.
```go
    if !VerifyShare(ShareSaving, AllCommitment) { //verify its own share
		panic("Fail to verify")
	}
	for _, s := range Shares {
		if !VerifyShare(s,  AllCommitment) { //verify shares it received
			panic("Fail to verify")
		}
	}
```
When receiving the key, the receiver should verify the shares, in this process, function abort immediately 
when it founds an invalid share. However, the `VerifyShare` takes constant time, thus, if a good statistician tries to perform the analysis
by changing some bits of the share, then all data he receives would be constant.

Anyway, Making the whole procedure constant time is not really hard, but makes no sense in this case.

##### When `Signing` 

No, there is no branching related to the keys. They just sign.

### 3. Avoid table look-ups indexed by secret data (No)

There is a discussion on https://crypto.stackexchange.com/questions/53528/why-dont-table-lookups-run-in-constant-time

Seems like it caused by CPU optimization Cache-missed. 

AES lookup table has this concern since its S-box indexing is really some secret, and it could be analyzed using statistic method.

The main concern is we should not use secret data as index, which really didn't happen in this algorithm, since the participant's index is not a secret.

But this is an interesting stuff to keep in mind. (I don't know if CUDA could help here, but I doubt it since it seems also facing Cache-missed problem)

### 4. Avoid secret-dependent loop bounds

## Reference

#### Source : https://gitlab.com/polychainlabs/threshold-ed25519

I referenced some bytes, bigInt conversion to implement some basic scalar element operation.

#### Source: https://github.com/agl/ed25519/edwards25519/scalarmult.go

I referenced this to implement a scalar inverse operation



