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

There is a discussion on [StackExchange](https://crypto.stackexchange.com/questions/53528/why-dont-table-lookups-run-in-constant-time)

Seems like it caused by CPU optimization Cache-missed. 

AES lookup table has this concern since its S-box indexing is really some secret, and it could be analyzed using statistic method.

The main concern is we should not use secret data as index, which really didn't happen in this algorithm, since the participant's index is not a secret.

But this is an interesting stuff to keep in mind. (I don't know if CUDA could help here, but I doubt it since it seems also facing Cache-missed problem)

### 4. Avoid secret-dependent loop bounds (No)

We don't use secret for bounds in a loop for this implementation.

But we should be careful that if the user controls the input of a function, which is pretty common since everyone has some sort of secret, then 
the bound of a loop should be constant or non-secret variable based.

Also note that we should always take good care of `Buffer overflow` problem (The Heartbleed Bug). Although Golang usually [checks bounds](https://golang.org/ref/spec#Index_expressions) for most of the usage.
But there might be issue with package [unsafe](https://golang.org/pkg/unsafe/), which has a description of usage on [this site](https://medium.com/a-journey-with-go/go-what-is-the-unsafe-package-d2443da36350).
It could increse the efficiency of the program, and it is in use for allowing converting pointer type (Not allowed without unsafe package).

Aside: [Exploitation Exercise with unsafe.Pointer in Go](https://dev.to/jlauinger/exploitation-exercise-with-unsafe-pointer-in-go-information-leak-part-1-1kga)

### 5. Prevent compiler interference with security-critical operations (Don't know)

When we want to delete some secret data on a computer, one way to do this is to overwrite the memory.
The [article](https://www.viva64.com/en/b/0178/) written by Andrey Karpov tells that. When trying to use `memset` in C to fill in zero to a block of memory,
the compiler could simply ignore it since this block of data won't be used anyway. As consequences, the secret data remains in the memory. One "might" steal the data 
by using buffer overflow.

(He also suggests using static code analyzers to detect potential errors)

**In the implementation**, the user potentially need to delete two things:

**a. Each user deletes the shares received from other.** 

(not reflected in function usage, we just assume the users delete them on their own if they are honest players)

**b. Consume one nonce pair from the preprocessed results after use.**

This was implemented by passing a pointer to an array, and remove the last element by
```go
*save = (*save)[:len(*save) - 1]
````
I doubt it would be a threat since Golang is not vulnerable towards buffer overflow. (without using `unsafe`)

#### Possible Solution:
1. look at the assembly code for the part involving security-critical code block

2. A function could be redefined as a `volatile` pointer, which prevents optimization from the compiler
```C
void * (*volatile memset_volatile)(void *, int, size_t) = memset
```

3. C11 introduced `memset_s`

4. Static code analyzers (Straight forward, I found a Plugin named as `Snyk`)

#### Static code analyzers result:

### 6. Prevent confusion between secure and insecure APIs

Security issue may be carried out when we call insecure API. 
Insecure API always has very similar functionality to the secure API, they may be implemented for optimization.
Some examples would be random number generator, and memory operations.

#### Possible Solution

1. change to the secure one, obviously

2. if we can't remove, wrap it with a secure function



## Reference

#### Source : https://gitlab.com/polychainlabs/threshold-ed25519

I referenced some bytes, bigInt conversion to implement some basic scalar element operation.

#### Source: https://github.com/agl/ed25519/edwards25519/scalarmult.go

I referenced this to implement a scalar inverse operation



