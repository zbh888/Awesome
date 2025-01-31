# FROST Implementation

[Flexible Round-Optimized Schnorr Threshold Signatures](https://crysp.uwaterloo.ca/software/frost/)

Using GoLand

```go

// Assume players all follow the rule
// This test details the whole procedure
// And if someone didn't follow the rule, error will show up like in other tests

func TestAlog3_CompleteMorePlayer(t *testing.T)
```

## Testing notes - Side Channel Attack

### Keygen

If the function `KeyGen` wrongly be used with some different number of players, or threshold, then this can be detected when distributing shares.
But, it doesn't hurt to at least perform a verification on commitment...

### Signing

Like said in the paper, there's also things can be done by the network issue. This implementation also checks the error caused by network issue, like
missing package due to network delay. I'm trying to make the user catch every reason why causing the failure.

Aggregation part has been tested by changing some parameter like message or nonce in the simple test to see if it returns invalid users.


### Things learned during testing

Handling error while considering security is something different from normal testing

1. Some error is simply usage error like wrongly entered the index. This type of error could clearly tell where is wrong like
"you entered the index 4, which should be 3 (your index)". But when meeting some issue related to security, the error message should
   be vague to hide information like "Verification fail". I believe if we can handle usage error and security error clearly,
   it will both benefit the users and ecosystem by enhancing usability and performance.
   
2. We should always be careful about side-channel attack when facing the code block involving the key information. 

## Some notes
I learned some useful skills to enhance the security of my code based on this
#### Source : [cryptocoding](https://github.com/veorq/cryptocoding)

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

&nbsp;

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

&nbsp;

### 3. Avoid table look-ups indexed by secret data (No)

There is a discussion on [StackExchange](https://crypto.stackexchange.com/questions/53528/why-dont-table-lookups-run-in-constant-time)

Seems like it caused by CPU optimization Cache-missed. 

AES lookup table has this concern since its S-box indexing is really some secret, and it could be analyzed using statistic method.

The main concern is we should not use secret data as index, which really didn't happen in this algorithm, since the participant's index is not a secret.

But this is an interesting stuff to keep in mind. (I don't know if CUDA could help here, but I doubt it since it seems also facing Cache-missed problem)

&nbsp;

### 4. Avoid secret-dependent loop bounds (No)

We don't use secret for bounds in a loop for this implementation.

But we should be careful that if the user controls the input of a function, which is pretty common since everyone has some sort of secret, then 
the bound of a loop should be constant or non-secret variable based.

Also note that we should always take good care of `Buffer overflow` problem (The Heartbleed Bug). Although Golang usually [checks bounds](https://golang.org/ref/spec#Index_expressions) for most of the usage.
But there might be issue with package [unsafe](https://golang.org/pkg/unsafe/), which has a description of usage on [this site](https://medium.com/a-journey-with-go/go-what-is-the-unsafe-package-d2443da36350).
It could increse the efficiency of the program, and it is in use for allowing converting pointer type (Not allowed without unsafe package).

&nbsp;

Aside: [Exploitation Exercise with unsafe.Pointer in Go](https://dev.to/jlauinger/exploitation-exercise-with-unsafe-pointer-in-go-information-leak-part-1-1kga)

### 5. Prevent compiler interference with security-critical operations (Don't know)

When we want to delete some secret data on a computer, one way to do this is to overwrite the memory.

The [article](https://www.viva64.com/en/b/0178/) written by Andrey Karpov tells that, when trying to use `memset` in C to fill in zero to a block of memory,
the compiler could simply ignore it since it knows this block of data won't be used anyway. As consequences, the secret data remains in the memory. One "might" steal the data 
by using buffer overflow like [this example](https://www.viva64.com/en/k/0041/), which passes a pointer to a function and request the specific length of buffer.

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

&nbsp;

### 6. Prevent confusion between secure and insecure APIs

Security issue may be carried out when we call insecure API. 
Insecure API always has very similar functionality to the secure API, they may be implemented for optimization.
Some examples would be random number generator, and memory operations.

#### Possible Solution

1. change to the secure one, obviously

2. if we can't remove, warn about its use

#### Example: Random

[Here](https://golang.org/src/crypto/rand/util.go?s=3070:3132#L96) we have the implementation of `crypto/rand`
, and [here](https://golang.org/pkg/math/rand/#Int) is the `Math/rand`

In this [tutorial](https://zetcode.com/golang/random/), it demonstrated the usages well.

But back to security, `Math/rand` takes the seed, and perform some known pseudo-random generating algorithm, which means, if two function take the same seed,
they give the same thing.

While `crypto/rand` use `io.Reader` that could read from `/dev/urandom`. That made a difference from an algorithm.
`/dev/urandom` generate the random number using hardware random-number generators, whose source is from real world around your computer.
They are physically unpredictable. 
 
`Math/rand` -> pseudo-random -> deterministic

`crypto/rand` -> hardware-random -> non-deterministic

Aside: [About](https://www.2uo.de/myths-about-urandom/) `dev/urandom`

### 7. Avoid mixing security and abstraction levels of cryptographic primitives in the same API layer

Suppose some experts wrote an API for RSA encryption, which involves padding.

```go
[]byte rsa(keys, encrypt: int, public: int, padding_method: string, data)
```

You have to specify the leading bytes and padding method, so there are 2 * 2 * 4=16 ways for you to use this API.

However, you don't know if your combining is safe or not. It might work for encryption or decryption but the method is vulnerable.

| 0 | 0 | pkcs1v15 | ☠: PKCS1 v1.5 decryption. Probably falls to Bleichenbacher’s attack. | (Not safe)

| 0 | 1 | pss | 🔒️: PSS signature. Great. | (safe)

**So, some suggestions when implementing API to myself**

From top to low:
1. Consider to make different versions for expert and usual programmer.

Sometimes, a programmer not related to cryptography doesn't need many functionality parameters for them to pass in.
They won't know the consequences even we specify the result. It takes time to learn. It is easier to just provide a high-level usage API.
They only need to know it is safe to use.

2. Process the parameters and decide if the usage is safe before running

Developer of API has the ability to warn the users that they use an unsafe combination of parameters. And they could possibly just raise a compile-time error
for completely meaningless arguments combination like none padding RSA.

3. Clearly label the safe package and unsafe package

Like `unsafe` package in Golang.

### 8. Use unsigned bytes to represent binary data

`byte is an alias for uint8` in Golang

However, some notes: signed char could raise some issue with overflow problem.

Like, `buf[32]` is a signed char buffer, and maybe you did something like `malloc(buf[0])`, then taking a negative value in malloc is equivalent as 
taking in a very big positive number, and you create a huge heap space for that, and the program may crush.





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
func KeyGen_send(index, threshold, NumPlayer uint32, str string) (PkgCommitment, []Share, Share, error)


//VerifyPkg : User receive the all PkgCommitments for all users and verify it.
//INPUT:
//       pkg, ([]PkgCommitment) : All PkgCommitments for all users
//                str, (string) : A context string to avoid replay attacks
//OUTPUT:
//                   ([]uint32) : A list of invalid users
//         ([]PublicCommitment) : All PkgCommitments for all users but without nonce commitments
func VerifyPkg(pkg []PkgCommitment, str string) ([]uint32, []PublicCommitment)


//DistributeShares : sender distributes the share to some receiver
//INPUTS:
//             sender, (uint32) : player that sends
//           receiver, (uint32) : player that sender wants to send
//            shares, ([]Share) : all shares f_sender(receiver), for all receivers
//OUTPUTS:
//                      (Share) : the share f_sender(receiver)
func DistributeShares(sender, receiver uint32, shares []Share) (Share, error)


//ReceiveAndGenKey : Collect the shares it received, and generate the key
//INPUTS:
//                  receiver, (uint32) : key generator
//                ShareSaving, (Share) : the share kept f_i(i)
// AllCommitment, ([]PublicCommitment) : Public commitments
//                   Shares ([]Shares) : shares they receives f_j(i), for all j
//OUTPUTS:
//                              (Keys) : the keys (secret and public)
//                        (PublicKeys) : the keys (only public)
func ReceiveAndGenKey(receiver uint32, ShareSaving Share, AllCommitment []PublicCommitment, Shares []Share) (Keys, PublicKeys, error)
```

### Signature Generation

Generate a signature

```go
//PreProcess : This can generate bunch of nonce and commitments for any player
//INPUTS:
//                    index, (uint32) : player index
//                    numSigns, (int) : how many signing operations is prepared
//OUTPUTS:
//       (PairOfNonceCommitmentsList) : Commitment use in public
// []TwoPairOfNonceCommitmentAndNonce : Nonce and their commitments saved for later use
func PreProcess(index uint32, numSigns int) (PairOfNonceCommitmentsList, []TwoPairOfNonceCommitmentAndNonce, error)

//SA_GenerateB : The aggregator combines nonce commitment and generate public nonce commitments list for signing party
//INPUTS:
//                             S, ([]uint32) : chosen signing party
//                         message, (string) : message it needs to be signed
// AllCommitments ([]PairOfNonceCommitments) : gathered commitments
//OUTPUTS:
//                  []PairOfNonceCommitments : public nonce commitments list for signing party, empty if any missing index detected
//                                    string : message
//                                  []uint32 : missing index in AllCommitments (network issue maybe)
func SA_GenerateB(S []uint32, message string ,AllCommitments []PairOfNonceCommitments) ([]PairOfNonceCommitments, string, []uint32)

//Sign : Player sign the message
//INPUTS:
//                            index, (uint32) : player index
//               B ([]PairOfNonceCommitments) : Nonce commitments for signing party
// save (*[]TwoPairOfNonceCommitmentAndNonce) : A pointer to the local storage of nonce commitment, removes the last element each time.
//                                keys (Keys) : secret keys
//OUTPUTS:
//                                  (Response): the signing result 
func Sign(index uint32, message string, B []PairOfNonceCommitments, save *[]TwoPairOfNonceCommitmentAndNonce, keys Keys) Response

//SA_GenerateSignature : Agregator collects responses and generate the result signature
//INPUTS:
//                      Group_PK (ed.Element) : player index
//                           message (string) : signing message
//               B ([]PairOfNonceCommitments) : Nonce commitments for signing party
//                     responses ([]Response) : All responses for signing party 
//                         Pks ([]PublicKeys) : Individual public keys
//OUTPUTS:
//                                (Signature) : Final signature 
//                                 ([]uint32) : Invalid users
func SA_GenerateSignature(Group_PK ed.Element, message string, B []PairOfNonceCommitments, responses []Response, Pks []PublicKeys) (Signature, []uint32)

// Verify: Everyone can verifies the message using GroupPublicKey, it returns message
// "Success to verify" or "Fail to verify" in constant time
func Verify(Signature Signature ,GroupPublicKey ed.Element, message string) string
```

## Reference

#### Source : [ed25519](https://gitlab.com/polychainlabs/threshold-ed25519)

I referenced some bytes, bigInt conversion to implement some basic scalar element operation.

#### Source: [scalarmult.go](https://github.com/agl/ed25519/edwards25519/scalarmult.go)

I referenced this to implement a scalar inverse operation



