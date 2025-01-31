---
title: "Anonymous Rate-Limited Credentials"
abbrev: "ARC"
category: info

docname: draft-yun-cfrg-arc-latest
submissiontype: IRTF
number:
date:
v: 3
venue:
  group: "Crypto Forum"
  type: ""
  mail: "cfrg@ietf.org"
  arch: "https://mailarchive.ietf.org/arch/browse/cfrg"
  github: "chris-wood/draft-arc"
  latest: "https://chris-wood.github.io/draft-arc/draft-yun-cfrg-arc.html"

author:
 -
    ins: C. Yun
    name: Cathie Yun
    organization: Apple, Inc.
    email: cathie@apple.com
 -
    ins: C. A. Wood
    name: Christopher A. Wood
    org: Apple, Inc.
    email: caw@heapingbits.net

normative:

informative:
  KVAC:
    title: Keyed-Verification Anonymous Credentials from Algebraic MACs
    target: https://eprint.iacr.org/2013/516
  REVISITING_KVAC:
    title: Revisiting Keyed-Verification Anonymous Credentials
    target: https://eprint.iacr.org/2024/1552
  BBS:
    title: Short Group Signatures
    target: https://eprint.iacr.org/2004/174
  BBDT17:
    title: Improved Algebraic MACs and Practical Keyed-Verification Anonymous Credentials
    target: https://link.springer.com/chapter/10.1007/978-3-319-69453-5_20
  NISTCurves: DOI.10.6028/NIST.FIPS.186-4
  SEC1:
    title: "SEC 1: Elliptic Curve Cryptography"
    target: https://www.secg.org/sec1-v2.pdf
    date: false
    author:
      -
        ins: Standards for Efficient Cryptography Group (SECG)

--- abstract

This document specifies the Anonymous Rate-Limited Credential (ARC) protocol,
a specialization of keyed-verification anonymous credentials with support for
rate limiting. ARC credentials can be presented from client to server up to
some fixed number of times, where each presentation is cryptographically bound
to client secrets and application-specific public information, such that each
presentation is unlinkable from the others as well as the original credential
creation. ARC is useful in applications where a server needs to throttle or
rate-limit access from anonymous clients.

--- middle

# Introduction

This document specifies the Anonymous Rate-Limited Credential (ARC) protocol,
a specialization of keyed-verification anonymous credentials with support for
rate limiting.

ARC is privately verifiable (keyed-verification), yet differs from similar token-based
protocols in that each credential can be presented multiple times without violating
unlinkability of different presentations. Servers issue credentials to clients that
are cryptographically bound to client secrets and some public information.
Afterwards, clients can present this credential to the server up to some fixed
number of times, where each presentation provides proof that it was derived
from a valid (previously issued) credential and bound to some public information.
Each presentation is pairwise unlinkable, meaning the server cannot link any two
presentations to the same client credential, nor can the server link a presentation
to the preceding credential issuance flow. Notably, the maximum number of
presentations from a credential is fixed by the application.

ARC is useful in settings where applications require a fixed number of zero-knowledge
proofs about client secrets that can also be cryptographically bound to some public
information. This capability lets servers use credentials in applications that need
throttled or rate-limited access from anonymous clients.

# Conventions and Definitions

## Notation and Terminology

The following functions and notation are used throughout the document.

- concat(x0, ..., xN): Concatenation of byte strings. For example,
  concat(0x01, 0x0203, 0x040506) = 0x010203040506.
- bytes_to_int and int_to_bytes: Convert a byte string to and from a non-negative integer.
  bytes_to_int and int_to_bytes are implemented as OS2IP and I2OSP as described in
  {{!RFC8017}}, respectively. Note that these functions operate on byte strings
  in big-endian byte order.
- random_integer_uniform(M, N): Generate a random, uniformly distributed integer R
  between M inclusive and N exclusive, i.e., M <= R < N.
- random_integer_uniform_excluding_set(M, N, S): Generate a random, uniformly
  distributed integer R between M inclusive and N exclusive, i.e., M <= R < N,
  such that R does not exist in the set of integers S.

All algorithms and procedures described in this document are laid out
in a Python-like pseudocode. Each function takes a set of inputs and parameters
and produces a set of output values. Parameters become constant values once the
protocol variant and the ciphersuite are fixed.

The notation `T U[N]` refers to an array called U containing N items of type
T. The type `opaque` means one single byte of uninterpreted data. Items of
the array are zero-indexed and referred as `U[j]` such that 0 <= j < N.
The notation `{T}` refers to a set consisting of elements of type `T`.
For any object `x`, we write `len(x)` to denote its length in bytes.

String values such as "CredentialRequest", "CredentialResponse", "Presentation", and "Tag"
are ASCII string literals.

The following terms are used throughout this document.

- Client: Protocol initiator. Creates a credential request, and uses the
corresponding server response to make a credential. The client can
make multiple presentations of this credential.
- Server: Computes a response to a credential request, with its
server private keys. Later the server can verify the client's presentations
with its private keys. Learns nothing about the client's secret attributes,
and cannot link a client's request/response and presentation steps.

<!-- TODO(caw): define these terms:
- tag
- attribute
- requestContext
- presentationContext
- presentationLimit
- presentation
-->

# Preliminaries

The construction in this document has one primary dependency:

- `Group`: A prime-order group implementing the API described below in {{pog}}.
  See {{ciphersuites}} for specific instances of groups.

## Prime-Order Group {#pog}

In this document, we assume the construction of an additive, prime-order
group `Group` for performing all mathematical operations. In prime-order groups,
any element (other than the identity) can generate the other elements of the
group. Usually, one element is fixed and defined as the group generator.
In the ARC setting, there are two fixed generator elements (generatorG, generatorH).
Such groups are uniquely determined by the choice of the prime `p` that defines the
order of the group. (There may, however, exist different representations
of the group for a single `p`. {{ciphersuites}} lists specific groups which
indicate both order and representation.)

The fundamental group operation is addition `+` with identity element
`I`. For any elements `A` and `B` of the group, `A + B = B + A` is
also a member of the group. Also, for any `A` in the group, there exists an element
`-A` such that `A + (-A) = (-A) + A = I`. Scalar multiplication by `r` is
equivalent to the repeated application of the group operation on an
element A with itself `r-1` times, this is denoted as `r*A = A + ... + A`.
For any element `A`, `p*A=I`. The case when the scalar multiplication is
performed on the group generator is denoted as `ScalarMultGen(r)`.
Given two elements A and B, the discrete logarithm problem is to find
an integer k such that B = k*A. Thus, k is the discrete logarithm of
B with respect to the base A.
The set of scalars corresponds to `GF(p)`, a prime field of order p, and are
represented as the set of integers defined by `{0, 1, ..., p-1}`.
This document uses types
`Element` and `Scalar` to denote elements of the group and its set of
scalars, respectively.

We now detail a number of member functions that can be invoked on a
prime-order group.

- Order(): Outputs the order of the group (i.e. `p`).
- Identity(): Outputs the identity element of the group (i.e. `I`).
- Generator(): Outputs the fixed generator of the group.
- HashToGroup(x, info): Deterministically maps
  an array of bytes `x` with domain separation value `info` to an element of `Group`. The map must ensure that,
  for any adversary receiving `R = HashToGroup(x, info)`, it is
  computationally difficult to reverse the mapping.
  Security properties of this function are described
  in {{!I-D.irtf-cfrg-hash-to-curve}}.
- HashToScalar(x, info): Deterministically maps
  an array of bytes `x` with domain separation value `info` to an element in GF(p).
  Security properties of this function are described in {{!I-D.irtf-cfrg-hash-to-curve, Section 10.5}}.
- RandomScalar(): Chooses at random a non-zero element in GF(p).
- ScalarInverse(s): Returns the inverse of input `Scalar` `s` on `GF(p)`.
- SerializeElement(A): Maps an `Element` `A`
  to a canonical byte array `buf` of fixed length `Ne`.
- DeserializeElement(buf): Attempts to map a byte array `buf` to
  an `Element` `A`, and fails if the input is not the valid canonical byte
  representation of an element of the group. This function can raise a
  DeserializeError if deserialization fails or `A` is the identity element of
  the group; see {{ciphersuites}} for group-specific input validation steps.
- SerializeScalar(s): Maps a `Scalar` `s` to a canonical
  byte array `buf` of fixed length `Ns`.
- DeserializeScalar(buf): Attempts to map a byte array `buf` to a `Scalar` `s`.
  This function can raise a DeserializeError if deserialization fails; see
  {{ciphersuites}} for group-specific input validation steps.

For each group, there exists two distinct generators, generatorG and
generatorH, generatorG = G.Generator() and generatorH = G.HashToGroup(G.SerializeElement(generatorG), "generatorH").
The group member functions GeneratorG() and GeneratorH() are shorthand
for returning generatorG and generatorH, respectively.

{{ciphersuites}} contains details for the implementation of this interface
for different prime-order groups instantiated over elliptic curves.

# ARC Protocol

The ARC protocol is a two-party protocol run between client and server
consisting of three distinct phases:

1. Key generation. In this phase, the server generates its private and public
   keys to be used for the remaining phases. This phase is described in {{setup}}.
2. Credential issuance. In this phase, the client and server interact to issue
   the client a credential that is cryptographically bound to client secrets.
   This phase is described in {{issuance}}.
3. Presentation. In this phase, the client uses the credential to create a "presentation"
   to the server, where the server learns nothing more than whether or not the
   presentation is valid and corresponds to some previously issued credential,
   without learning which credential it corresponds to. This phase is described
   in {{presentation}}.

This protocol bears resemblance to anonymous token protocols, such as those built on
Blind RSA {{?BLIND-RSA=RFC9474}} and Oblivious Pseudorandom Functions {{?OPRFS=RFC9497}}
with one critical distinction: unlike anonymous tokens, an anonymous credential can be
used multiple times to create unlinkable presentations (up to the fixed presentation
limit). This means that a single issuance invocation can drive multiple presentation
invocations, whereas with anonymous tokens, each presentation invocation requires
exactly one issuance invocation. As a result, credentials are generally longer lived
than tokens. Applications configure the credential presentation limit after the
credential is issued such that client and server agree on the limit during presentation.
Servers are responsible for ensuring this limit is not exceeded. Clients that exceed
the agreed-upon presentation limit break the unlinkability guarantees provided by
the protocol.

The rest of this section describes the three phases of the ARC protocol.

## Key Generation {#setup}

In the key generation phase, the server generates its private and public
keys, denoted ServerPrivateKey and ServerPublicKey, as follows.

~~~
Input: None
Output:
- ServerPrivateKey:
  - x0: Scalar
  - x1: Scalar
  - x2: Scalar
  - x0Blinding: Scalar
- ServerPublicKey:
  - X0: Element
  - X1: Element
  - X2: Element

Parameters
- Group G

def SetupServer():
  x0 = G.RandomScalar()
  x1 = G.RandomScalar()
  x2 = G.RandomScalar()
  x0Blinding = G.RandomScalar()
  X0 = x0 * G.GeneratorG() + x0Blinding * G.GeneratorH()
  X1 = x1 * G.GeneratorH()
  X2 = x2 * G.GeneratorH()
  return ServerPrivateKey(x0, x1, x2, x0Blinding), ServerPublicKey(X0, X1, X2)
~~~

The server public keys can be serialized as follows:

~~~
struct {
  uint8 X0[Ne]; // G.SerializeElement(X0)
  uint8 X1[Ne]; // G.SerializeElement(X1)
  uint8 X2[Ne]; // G.SerializeElement(X2)
} ServerPublicKey;
~~~

The length of this encoded response structure is `NserverPublicKey = 3*Ne`.

## Issuance {#issuance}

The purpose of the issuance phase is for the client and server to cooperatively compute a credential
that is cryptographically bound to the client's secrets. Clients do not choose these secrets;
they are computed by the protocol.

The issuance phase of the protocol requires clients to know the server public key a priori, as well as
an arbitrary, application-specific request context. It requires no other input. It consists of three
distinct steps:

1. The client generates and sends a credential request to the server. This credential request contains a
   proof that the request is valid with respect to the client's secrets and request context. See
   {{issuance-step1}} for details about this step.
1. The server validates the credential request. If valid, it computes a credential response with the server
   private keys. The response includes a proof that the credential response is valid with respect to the
   server keys. The server sends the response to the client. See {{issuance-step2}} for details about this
   step.
1. The client finalizes the credential by processing the server response. If valid, this step yields a
   credential that can then be used in the presentation phase of the protocol. See {{issuance-step3}} for
   details about this step.

Each of these steps are described in the following subsections.

### Credential Request {#issuance-step1}

Given a request context, the process for creating a credential request is as follows:

~~~
(clientSecrets, request) = CredentialRequest(requestContext)

Inputs:
- requestContext: Data, context for the credential request

Outputs:
- request:
  - m1Enc: Element, first encrypted secret.
  - m2Enc: Element, second encrypted secret.
  - requestProof: ZKProof, a proof of correct generation of m1Enc and m2Enc.
- clientSecrets:
  - m1: Scalar, first secret.
  - m2: Scalar, second secret.
  - r1: Scalar, blinding factor for first secret.
  - r2: Scalar, blinding factor for second secret.

Parameters:
- G: Group
- generatorG: Element, equivalent to G.GeneratorG()
- generatorH: Element, equivalent to G.GeneratorH()

def CredentialRequest(requestContext):
  m1 = G.RandomScalar()
  m2 = G.HashToScalar(requestContext, "requestContext")
  r1 = G.RandomScalar()
  r2 = G.RandomScalar()
  m1Enc = m1 * generatorG + r1 * generatorH
  m2Enc = m2 * generatorG + r2 * generatorH
  requestProof = MakeCredentialRequestProof(m1, m2, r1, r2, m1Enc, m2Enc)
  request = (m1Enc, m2Enc, requestProof)
  clientSecrets = (m1, m2, r1, r2)
  return (clientSecrets, request)
~~~

See {{request-proof}} for more details on the generation of the credential request proof.

The resulting request can be serialized as follows.

~~~
struct {
  uint8 m1Enc[Ne];
  uint8 m2Enc[Ne];
  uint8 challenge[Ns];
  uint8 response0[Ns];
  uint8 response1[Ns];
  uint8 response2[Ns];
  uint8 response3[Ns];
} CredentialRequest;
~~~

The length of this encoded request structure is `Nrequest = 2*Ne + 5*Ns`.

### Credential Response {#issuance-step2}

Given a credential request and server public and private keys, the process
for creating a credential response is as follows.

~~~ psuedocode
response = CredentialResponse(serverPrivateKey, serverPublicKey, request)

Inputs:
- serverPrivateKey:
  - x0: Scalar (private), server private key 0.
  - x1: Scalar (private), server private key 1.
  - x2: Scalar (private), server private key 2.
  - x0Blinding: Scalar (private), blinding value for x0.
- serverPublicKey:
  - X0: Element, server public key 0.
  - X1: Element, server public key 1.
  - X2: Element, server public key 2.
- request:
  - m1Enc: Element, first encrypted secret.
  - m2Enc: Element, second encrypted secret.
  - requestProof: ZKProof, a proof of correct generation of m1Enc and m2Enc.

Outputs:
- U: Element, a randomized generator for the response, `b*G`.
- encUPrime: Element, encrypted UPrime.
- X0Aux: Element, auxiliary point for X0.
- X1Aux: Element, auxiliary point for X1.
- X2Aux: Element, auxiliary point for X2.
- HAux: Element, auxiliary point for generatorH.
- responseProof: ZKProof, a proof of correct generation of
  U, encUPrime, server public keys, and auxiliary points.

Parameters:
- G: Group
- generatorG: Element, equivalent to G.GeneratorG()
- generatorH: Element, equivalent to G.GeneratorH()

Exceptions:
- VerifyError, raised when response verification fails

def CredentialResponse(serverPrivateKeys, serverPublicKey, request):
  if VerifyCredentialRequestProof(request) == false:
    raise VerifyError

  b = G.RandomScalar()
  U = b * generatorG
  encUPrime = b * (serverPublicKey.X0 +
        serverPrivateKeys.x1 * request.m1Enc +
        serverPrivateKeys.x2 * request.m2Enc)
  X0Aux = b * serverPrivateKeys.x0Blinding * generatorH
  X1Aux = b * serverPublicKey.X1
  X2Aux = b * serverPublicKey.X2
  HAux = b * generatorH

  responseProof = MakeCredentialResponseProof(serverPrivateKey,
    serverPublicKey, request, b, U, encUPrime, X0Aux, X1Aux, X2Aux, HAux)
  return (U, encUPrime, X0Aux, X1Aux, X2Aux, HAux, responseProof)
~~~

The resulting response can be serialized as follows. See {{response-proof}} for more details on the generation of the credential response proof.

~~~
struct {
  uint8 U[Ne];
  uint8 encUPrime[Ne];
  uint8 X0Aux[Ne];
  uint8 X1Aux[Ne];
  uint8 X2Aux[Ne];
  uint8 HAux[Ne];
  uint8 challenge[Ns];
  uint8 response0[Ns];
  uint8 response1[Ns];
  uint8 response2[Ns];
  uint8 response3[Ns];
  uint8 response4[Ns];
  uint8 response5[Ns];
  uint8 response6[Ns];
}
~~~

The length of this encoded response structure is `Nresponse = 6*Ne + 8*Ns`.

### Finalize Credential {#issuance-step3}

Given a credential request and response, server public keys, and the client
secrets produced when creating a credential request, the process for
finalizing the issuance flow and creating a credential is as follows.

~~~
credential = FinalizeCredential(clientSecrets, serverPublicKey, request, response)

Inputs:
- clientSecrets:
  - m1: Scalar, first secret.
  - m2: Scalar, second secret.
  - r1: Scalar, blinding factor for first secret.
  - r2: Scalar, blinding factor for second secret.
- serverPublicKey: ServerPublicKey, shared with the client out-of-band
- request:
  - m1Enc: Element, first encrypted secret.
  - m2Enc: Element, second encrypted secret.
  - requestProof: ZKProof, a proof of correct generation of m1Enc and m2Enc.
- response:
  - U: Element, a randomized generator for the response. `b*G`.
  - encUPrime: Element, encrypted UPrime.
  - X0Aux: Element, auxiliary point for X0.
  - X1Aux: Element, auxiliary point for X1.
  - X2Aux: Element, auxiliary point for X2.
  - HAux: Element, auxiliary point for generatorH.
  - responseProof: ZKProof, a proof of correct generation of U, encUPrime, server public keys, and auxiliary points.

Outputs:
- credential:
  - m1: Scalar, client's first secret.
  - U: Element, a randomized generator for the response. `b*G`.
  - UPrime: Element, the MAC over the server's private keys and the client's secret secrets.
  - X1: Element, server public key 1.

Exceptions:
- VerifyError, raised when response verification fails

Parameters:
- G: Group
- generatorG: Element, equivalent to G.GeneratorG()
- generatorH: Element, equivalent to G.GeneratorH()

def FinalizeCredential(clientSecrets, serverPublicKey, request, response):
  if VerifyCredentialResponseProof(serverPublicKey, response, request) == false:
    raise VerifyError
  UPrime = response.encUPrime - response.X0Aux - clientSecrets.r1 * response.X1Aux - clientSecrets.r2 * response.X2Aux
  return (clientSecrets.m1, response.U, UPrime, serverPublicKey.X1)
~~~

## Presentation {#presentation}

The purpose of the presentation phase is for the client to create a "presentation" to the server
which can be verified using the server private key. This phase is non-interactive, i.e., there is
no state stored between client and server in order to produce and then verify a presentation.
Client and server agree upon a fixed limit of presentations in order to create and verify
presentations; presentations will not verify correctly if the client and server use different
limits.

This phase consists of three steps:

1. The client creates a presentation state for a given presentation context and presentation limit.
   This state is used to produce a fixed amount of presentations.
1. The client creates a presentation from the presentation state and sends it to the server.
   The presentation is cryptographically bound to the state's presentation context, and
   contains proof that the presentation is valid with respect to the presentation context.
   Moreover, the presentation contains proof that the count of this presentation is within the
   presentation limit.
1. The server verifies the presentation with respect to the presentation context and presentation
   limit.

Details for each each of these steps are in the following subsections.

## Presentation State

Presentation state is used to track the number of presentations for a given credential.
This state is important for ARC's unlinkability goals: reuse of state can break
unlinkability properties of credential presentations. State is initialized
with a credential, presentation context, and presentation limit. It is then mutated
after each presentation construction (as described in {{presentation-construction}}).

~~~
state = MakePresentationState(credential, presentationContext, presentationLimit)

Inputs:
- credential:
  - m1: Scalar, client's first secret.
  - U: Element, a randomized generator for the response `b*G`.
  - UPrime: Element, the MAC over the server's private keys and the client's secrets.
  - X1: Element, server public key 1.
- presentationContext: Data (public), used for presentation tag computation.
- presentationLimit: Integer, the fixed presentation limit.

Outputs:
- credential
- presentationContext: Data (public), used for presentation tag computation.
- presentationNonceSet: {Integer}, the set of nonces that have been used for this presentation
- presentationCount: Integer, the number of times this credential has been presented for this presentationContext, initialized to 0.
- presentationLimit: Integer, the fixed presentation limit.

def MakePresentationState(credential, presentationContext, presentationLimit):
  nonce = random_integer_uniform(0, presentationLimit)
  return PresentationState(credential, presentationContext, [nonce], presentationLimit)
~~~

## Presentation Construction {#presentation-construction}

Creating a presentation requires a credential, presentation context, and presentation limit.
This process is necessarily stateful on the client since the number of times a credential
is used for a given presentation context cannot exceed the presentation limit; doing so
would break presentation unlinkability, as two presentations created with the same "counter"
can be directly compared for equality (via the "tag"). As a result, the process for creating
a presentation accepts as input a presentation count and then outputs an updated presentation
count.

~~~
newState, presentation = Present(state)

Inputs:
state: input PresentationState
  - credential
  - presentationContext: Data (public), used for presentation tag computation.
  - presentationNonceSet: {Integer}, the set of nonces that have been used for this presentation
  - presentationCount: Integer, the number of times this credential has been presented for this presentationContext, initialized to 0.
  - presentationLimit: Integer, the fixed presentation limit.

Outputs:
- newState: updated PresentationState
- presentation:
  - U: Element, re-randomized from the U in the response.
  - UPrimeCommit: Element, a public key to the issued UPrime.
  - m1Commit: Element, a public key to the client secret (m1).
  - nonce: Integer, the nonce associated with this presentation.
  - tag: Element, the tag element used for enforcing rate limiting and reuse.
  - presentationProof: ZKProof, a proof of correct generation of the presentation.

Parameters:
- G: Group
- generatorG: Element, equivalent to G.GeneratorG()
- generatorH: Element, equivalent to G.GeneratorH()

Exceptions:
- LimitExceededError, raised when the presentation count meets or exceeds the presentation limit for the given presentation context

def Present(state):
  if state.presentationCount >= state.presentationLimit:
    raise LimitExceededError

  a = G.RandomScalar()
  r = G.RandomScalar()
  z = G.RandomScalar()

  U = a * state.credential.U
  UPrime = a * state.credential.UPrime
  UPrimeCommit = UPrime + r * generatorG
  m1Commit = state.credential.m1 * U + z * generatorH

  # This step mutates the state by keeping track of
  # what nonces have already been spent.
  nonce = random_integer_uniform_excluding_set(0,
    state.presentationLimit, state.presentationNonceSet)
  state.presentationNonceSet.add(nonce)
  state.presentationCount += 1

  generatorT = G.HashToGroup(presentationContext, "Tag")
  tag = (credential.m1 + nonce)^(-1) * generatorT
  V = z * credential.X1 - r * generatorG
  m1Tag = state.credential.m1 * tag

  presentationProof = MakePresentationProof(U, UPrimeCommit, m1Commit, tag, generatorT, credential, V, r, z, nonce, m1Tag)

  presentation = (U, UPrimeCommit, m1Commit, nonce, tag, presentationProof)

  return state, presentation
~~~

[[OPEN ISSUE: should the tag also fold in the presentation limit?]]

The resulting presentation can be serialized as follows. See {{presentation-proof}}
for more details on the generation of the presentation proof.

~~~
struct {
  uint8 U[Ne];
  uint8 UPrimeCommit[Ne];
  uint8 m1Commit[Ne];
  uint8 tag[Ne];
  uint8 challenge[Ns];
  uint8 response0[Ns];
  uint8 response1[Ns];
  uint8 response2[Ns];
  uint8 response3[Ns];
  uint8 response4[Ns];
}
~~~

The length of this structure is `Npresentation = 4*Ne + 6*Ns`.

## Presentation Verification

The server processes the presentation by verifying the presentation proof against server-computed
values, and performing a check that the presentation conforms to the presentation limit.

~~~
validity = VerifyPresentation(serverPrivateKey, serverPublicKey, requestContext, presentationContext, presentation, presentationLimit)

Inputs:
- serverPrivateKey:
  - x0: Scalar (private), server private key 0.
  - x1: Scalar (private), server private key 1.
  - x2: Scalar (private), server private key 2.
  - x0Blinding: Scalar (private), blinding value for x0.
- serverPublicKey:
  - X0: Element, server public key 0.
  - X1: Element, server public key 1.
  - X2: Element, server public key 2.
- requestContext: Data, context for the credential request.
- presentationContext: Data (public), used for presentation tag computation.
- presentation:
  - U: Element, re-randomized from the U in the response.
  - UPrimeCommit: Element, a public key to the issued UPrime.
  - m1Commit: Element, a public key to the client secret (m1).
  - nonce: Integer, the nonce associated with this presentation.
  - tag: Element, the tag element used for enforcing rate limiting and reuse.
  - presentationProof: ZKProof, a proof of correct generation of the presentation.
- presentationLimit: Integer, the fixed presentation limit.

Outputs:
- validity: Boolean, True if the presentation is valid, False otherwise.

Parameters:
- G: Group
- generatorG: Element, equivalent to G.GeneratorG()
- generatorH: Element, equivalent to G.GeneratorH()

Exceptions:
- InvalidNonceError, raised when the nonce associated with the presentation is invalid

def VerifyPresentation(serverPrivateKey, serverPublicKey, requestContext, presentationContext, presentation, presentationLimit):
  if presentation.nonce < 0 or presentation.nonce > presentationLimit:
    raise InvalidNonceError

  generatorT = G.HashToGroup(presentationContext, "Tag")
  m1Tag = generatorT - (presentation.nonce * presentation.tag)

  validity = VerifyPresentationProof(serverPrivateKey, serverPublicKey, requestContext, presentationContext, presentation, m1Tag)
  # Implementation-specific step: perform double-spending check on tag.
  # Implementation-specific step: store tag for future double-spending check.
  return validity
~~~

Implementation-specific steps: the server must perform a check that the tag (presentation.tag) has
not previously been seen, to prevent double spending. It then stores the tag for use in future double
spending checks. To reduce the overhead of performing double spend checks, the server can store and
look up the tags corresponding to the associated requestContext and presentationContext values.

# Zero-Knowledge Proofs

This section describes a Schnorr proof compiler that is used for the construction of other proofs needed throughout
the ARC protocol. {{compiler}} describes the compiler, and the remaining sections describe how it is used for
the purposes of producing ARC proofs.

## Schnorr Compiler {#compiler}

The compiler specified in this section automates the Fiat-Shamir transform that is often used to
transform interactive zero-knowledge proofs into non-interactive proofs such that they can be used
to non-interactively prove various statements of importance in higher-level protocols, such as ARC.
The compiler consists of a prover and verifier role. The prover constructs a transcript for the
proof and then applies the Fiat-Shamir heuristic to generate the resulting challenge and response
values. The verifier reconstructs the same transcript to verify the proof.

The prover and verifier roles are specified below in {{prover}} and {{verifier}}, respectively.

### Prover

The prover role consists of four functions:

- AppendScalar: This function adds a scalar representation to the transcript.
- AppendElement: This function adds an element representation to the transcript.
- Constrain: This function applies an explicit constraint to the proof, where the constraint is expressed as equality between some element and a linear combination of scalar and element representations. An example constraint might be `Z = aX + bY`, for scalars `a`, `b`, and elements
`X`, `Y`, `Z`.
- Prove: This function applies the Fiat-Shamir heuristic to the protocol transcript and set of
constraints to produce a zero-knowledge proof that can be verified.

These functions are defined in the following sub-sections.

In addition, the prover role consists of the following state:

- label: Data, a value representing the context in which the proof will be used
- scalars: [Integer], An ordered set of representation of scalar variables to use in the proof. Each scalar has a label associated with it, stored in a list called `scalar_labels`.
- elements: [Integer], An ordered set of representation of element variables to use in the proof. Each element has a label associated with it, stored in a list called `element_labels`.
- constraints: a set of constraints, where each constraint consists of a constraint element and a linear combination of variables.

#### AppendScalar

~~~
AppendScalar(label, assignment)

Inputs:
- label: Data, Scalar variable label
- assignment: Scalar variable

Outputs:
- Integer: Integer representation of the new scalar variable

def AppendScalar(label, assignment):
  state.scalars.append(assignment)
  state.scalar_labels.append(label)
  return len(state.scalars) - 1
~~~

#### AppendElement

~~~
AppendElement(label, assignment)

Inputs:
- label: Data, Element variable label
- assignment: Element variable

Outputs:
- Integer: Integer representation of the new element variable

def AppendElement(label, assignment):
  state.elements.append(assignment)
  state.element_labels.append(label)
  return len(state.elements) - 1
~~~

#### Constrain

~~~
Constrain(result, linearCombination)

Inputs:
- result: Integer, representation of constraint element
- assignment: linear combination of scalar and element variable (representations)

def Constrain(label, linearCombination):
  state.constraints.append((result, linearCombination))
~~~

#### Prove

The Prove function is defined below.

~~~
Prove()

Outputs:
- ZKProof, a proof consisting of a challenge Scalar and then fixed number of response Scalar values

Parameters:
- G: Group
- generatorG: Element, equivalent to G.GeneratorG()
- generatorH: Element, equivalent to G.GeneratorH()

Exceptions:
- InvalidVariableAllocationError, raised when the prover was incorrectly configured

def Prove():
  blindings = [G.RandomScalar() for i in range(len(state.scalars))]

  blinded_elements = []
  for (constraint_point, linear_combination) in state.constraints:
    if constraint_point.index > len(state.elements):
      raise InvalidVariableAllocationError

    for (scalar_var, element_var) in linear_combination:
      if scalar_var.index > len(state.scalars):
        raise InvalidVariableAllocationError
      if element_var.index > len(state.elements):
        raise InvalidVariableAllocationError

    scalar_index = linear_combination[0][0]
    element_index = linear_combination[0][1]
    blinded_element = blindings[scalar_index] * state.elements[element_index]

    for i, pair in enumerate(linear_combination):
      if i > 0:
        scalar_index = pair[0]
        element_index = pair[1]
        blinded_element += blindings[scalar_index] * state.elements[element_index]

        blinded_elements.append(blinded_element)

  # Obtain a scalar challenge
  challenge = ComposeChallenge(state.label, state.elements, blinded_elements)

  # Compute response scalars from the challenge, scalars, and blindings.
  responses = []
  for (index, scalar) in enumerate(state.scalars):
    blinding = blindings[index]
    responses.append(blinding - challenge * scalar)

  return ZKProof(challenge, responses)
~~~

The function ComposeChallenge is defined below.

~~~
ComposeChallenge(label, elements, blinded_elements)

Inputs:
- label: Data, the proof label
- elements: [Element], ordered list of elements
- blinded_elements: [Element], ordered list of blinded elements

Outputs:
- challenge, Scalar

Parameters:
- G: Group
- generatorG: Element, equivalent to G.GeneratorG()
- generatorH: Element, equivalent to G.GeneratorH()

def ComposeChallenge(label, elements, blinded_elements):
  challenge_input = Data() # Empty Data

  for element in elements:
    serialized_element = G.SerializeElement(element)
    challenge_input += I2OSP(len(serialized_element), 2) + serialized_element

  for blinded_element in blinded_elements:
    serialized_blinded_element = G.SerializeElement(blinded_element)
    challenge_input += I2OSP(len(serialized_blinded_element), 2) + serialized_blinded_element

  return G.HashToScalar(challenge_input, label)
~~~

### Verifier {#verifier}

The verifier role consists of four functions:

- AppendScalar: This function adds a scalar representation to the transcript.
- AppendElement: This function adds an element representation to the transcript.
- Constrain: This function applies an explicit constraint to the proof, where the constraint is expressed as equality between some element and a linear combination of scalar and element representations. An example constraint might be `Z = aX + bY`, for scalars `a`, `b`, and elements
`X`, `Y`, `Z`.
- Verify: This function applies the Fiat-Shamir heuristic to verify the zero-knowledge proof.

AppendScalar and Verify are defined in the following sub-sections. AppendElement and Constrain matches the functionality used in the prover role.

#### AppendScalar

~~~
AppendScalar(label)

Inputs:
- label: Data, Scalar variable label

Outputs:
- Integer: Integer representation of the new scalar variable

def AppendScalar(label):
  state.scalar_labels.append(label)
  return len(state.scalar_labels) - 1
~~~

#### Verify

~~~
Verify(proof)

Inputs:
- ZKProof, a proof consisting of a challenge Scalar and then fixed number of response Scalar values

Outputs:
- Boolean, True if the proof is valid, False otherwise.

Parameters:
- G: Group
- generatorG: Element, equivalent to G.GeneratorG()
- generatorH: Element, equivalent to G.GeneratorH()

Exceptions:
- InvalidVariableAllocationError, raised when the prover was incorrectly configured

def Verify(proof):
  if len(state.elements) != len(state.element_labels):
    raise InvalidVariableAllocationError

  blinded_elements = []
  for (constraint_element, linear_combination) in state.constraints:
    if constraint_element > len(state.elements):
      raise InvalidVariableAllocationError
    for (_, element_var) in linear_combination:
      if element_var > len(state.elements):
        raise InvalidVariableAllocationError

    challenge_element = proof.challenge * state.elements[constraint_element]
    for i, pair in enumerate(linear_combination):
      challenge_element += proof.responses[pair[0]] * state.elements[pair[1]]

    blinded_elements.append(challenge_element)

  challenge = ComposeChallenge(state.label, self.elements, blinded_elements)
  return challenge == proof.challenge
~~~

## CredentialRequest Proof {#request-proof}

The request proof is a proof of knowledge of (m1, m2, r1, r2) used to generate the encrypted request. Statements to prove:

~~~
1. m1Enc = m1 * generatorG + r1 * generatorH
2. m2Enc = m2 * generatorG + r2 * generatorH
~~~

### CredentialRequest Proof Creation

~~~
requestProof = MakeCredentialRequestProof(m1, m2, r1, r2, m1Enc, m2Enc)

Inputs:
- m1: Scalar, first secret.
- m2: Scalar, second secret.
- r1: Scalar, blinding factor for first secret.
- r2: Scalar, blinding factor for second secret.
- m1Enc: Element, first encrypted secret.
- m2Enc: Element, second encrypted secret.

Outputs:
- proof: ZKProof
  - challenge: Scalar, the challenge used in the proof of valid encryption.
  - response0: Scalar, the response corresponding to m1.
  - response1: Scalar, the response corresponding to m2.
  - response2: Scalar, the response corresponding to r1.
  - response3: Scalar, the response corresponding to r2.

Parameters:
- G: Group
- generatorG: Element, equivalent to G.GeneratorG()
- generatorH: Element, equivalent to G.GeneratorH()
- contextString: public input

def MakeCredentialRequestProof(m1, m2, r1, r2, m1Enc, m2Enc):
  prover = Prover(contextString + "CredentialRequest")

  m1Var = prover.AppendScalar("m1", m1)
  m2Var = prover.AppendScalar("m2", m2)
  r1Var = prover.AppendScalar("r1", r1)
  r2Var = prover.AppendScalar("r2", r2)

  genGVar = prover.AppendElement("genG", generatorG)
  genHVar = prover.AppendElement("genH", generatorH)
  m1EncVar = prover.AppendElement("m1Enc", m1Enc)
  m2EncVar = prover.AppendElement("m2Enc", m2Enc)

  # 1. m1Enc = m1 * generatorG + r1 * generatorH
  prover.Constrain(m1EncVar, [(m1Var, genGVar), (r1Var, genHVar)])

  # 2. m2Enc = m2 * generatorG + r2 * generatorH
  prover.Constrain(m2EncVar, [(m2Var, genGVar), (r2Var, genHVar)])

  return prover.Prove()
~~~

### CredentialRequest Proof Verification

~~~
validity = VerifyCredentialRequestProof(request)

Inputs:
- request:
  - m1Enc: Element, first encrypted secret.
  - m2Enc: Element, second encrypted secret.
  - requestProof: ZKProof, a proof of correct generation of m1Enc and m2Enc.
    - challenge: Scalar, the challenge used in the proof of valid encryption.
    - response0: Scalar, the response corresponding to m1.
    - response1: Scalar, the response corresponding to m2.
    - response2: Scalar, the response corresponding to r1.
    - response3: Scalar, the response corresponding to r2.

Outputs:
- validity: Boolean, True if the proof verifies correctly, False otherwise.

Parameters:
- G: group
- generatorG: Element, equivalent to G.GeneratorG()
- generatorH: Element, equivalent to G.GeneratorH()
- contextString: public input

def VerifyCredentialRequestProof(request):
  verifier = Verifier(contextString + "CredentialRequest")

  m1Var = verifier.AppendScalar("m1")
  m2Var = verifier.AppendScalar("m2")
  r1Var = verifier.AppendScalar("r1")
  r2Var = verifier.AppendScalar("r2")

  genGVar = verifier.AppendElement("genG", generatorG)
  genHVar = verifier.AppendElement("genH", generatorH)
  m1EncVar = verifier.AppendElement("m1Enc", request.m1Enc)
  m2EncVar = verifier.AppendElement("m2Enc", request.m2Enc)

  # 1. m1Enc = m1 * generatorG + r1 * generatorH
  verifier.Constrain(m1EncVar, [(m1Var, genGVar), (r1Var, genHVar)])

  # 2. m2Enc = m2 * generatorG + r2 * generatorH
  verifier.Constrain(m2EncVar, [(m2Var, genGVar), (r2Var, genHVar)])

  return verifier.Verify(request.proof)
~~~

## CredentialResponse Proof {#response-proof}

The response proof is a proof of knowledge of (x0, x1, x2, x0Blinding, b) used in the server's CredentialResponse for the client's CredentialRequest. Statements to prove:

~~~
1. X0 = x0 * generatorG + x0Blinding * generatorH
2. X1 = x1 * generatorH
3. X2 = x2 * generatorH
4. X0Aux = b * x0Blinding * generatorH
  4a. HAux = b * generatorH
  4b: X0Aux = x0Blinding * HAux (= b * x0Blinding * generatorH)
5. X1Aux = b * x1 * generatorH
  5a. X1Aux = b * X1 (X1 = x1 * generatorH)
  5b. X1Aux = t1 * generatorH (t1 = b * x1)
6. X2Aux = b * x2 * generatorH
  6a. X2Aux = b * X2 (X2 = x2 * generatorH)
  6b. X2Aux = t2 * generatorH (t2 = b * x2)
7. U = b * generatorG
8. encUPrime = b * (X0 + x1 * Enc(m1) + x2 * Enc(m2))
~~~

### CredentialResponse Proof Creation

~~~
responseProof = MakeCredentialResponseProof(serverPrivateKey, serverPublicKey, request, b, U, encUPrime, X0Aux, X1Aux, X2Aux, HAux)

Inputs:
- serverPrivateKey:
  - x0: Scalar (private), server private key 0.
  - x1: Scalar (private), server private key 1.
  - x2: Scalar (private), server private key 2.
  - x0Blinding: Scalar (private), blinding value for x0.
- serverPublicKey:
  - X0: Element, server public key 0.
  - X1: Element, server public key 1.
  - X2: Element, server public key 2.
- request:
  - m1Enc: Element, first encrypted secret.
  - m2Enc: Element, second encrypted secret.
  - requestProof: ZKProof, a proof of correct generation of m1Enc and m2Enc.
- encUPrime: Element, encrypted UPrime.
- X0Aux: Element, auxiliary point for X0.
- X1Aux: Element, auxiliary point for X1.
- X2Aux: Element, auxiliary point for X2.
- HAux: Element, auxiliary point for generatorH.

Outputs:
- proof: ZKProof
  - challenge: Scalar, the challenge used in the proof of valid response.
  - response0: Scalar, the response corresponding to x0.
  - response1: Scalar, the response corresponding to x1.
  - response2: Scalar, the response corresponding to x2.
  - response3: Scalar, the response corresponding to x0Blinding.
  - response4: Scalar, the response corresponding to b.
  - response5: Scalar, the response corresponding to t1.
  - response6: Scalar, the response corresponding to t2.

Parameters:
- G: Group
- generatorG: Element, equivalent to G.GeneratorG()
- generatorH: Element, equivalent to G.GeneratorH()
- contextString: public input

def MakeCredentialResponseProof(serverPrivateKey, serverPublicKey, request, b, U, encUPrime, X0Aux, X1Aux, X2Aux, HAux):
  prover = Prover(contextString + "CredentialResponse")

  x0Var = prover.AppendScalar("x0", serverPrivateKey.x0)
  x1Var = prover.AppendScalar("x1", serverPrivateKey.x1)
  x2Var = prover.AppendScalar("x2", serverPrivateKey.x2)
  x0BlindingVar = prover.AppendScalar("x0Blinding", serverPrivateKey.x0Blinding)
  bVar = prover.AppendScalar("b", b)
  t1Var = prover.AppendScalar("t1", b * serverPrivateKey.x1)
  t2Var = prover.AppendScalar("t2", b * serverPrivateKey.x2)

  genGVar = prover.AppendElement("genG", generatorG)
  genHVar = prover.AppendElement("genH", generatorH)
  m1EncVar = prover.AppendElement("m1Enc", request.m1Enc)
  m2EncVar = prover.AppendElement("m2Enc", request.m2Enc)
  UVar = prover.AppendElement("U", U)
  encUPrimeVar = prover.AppendElement("encUPrime", encUPrime)
  X0Var = prover.AppendElement("X0", serverPublicKey.X0)
  X1Var = prover.AppendElement("X1", serverPublicKey.X1)
  X2Var = prover.AppendElement("X2", serverPublicKey.X2)
  X0AuxVar = prover.AppendElement("X0Aux", X0Aux)
  X1AuxVar = prover.AppendElement("X1Aux", X1Aux)
  X2AuxVar = prover.AppendElement("X2Aux", X2Aux)
  HAuxVar = prover.AppendElement("HAux", HAux)

  # 1. X0 = x0 * generatorG + x0Blinding * generatorH
  prover.Constrain(X0Var, [(x0Var, genGVar), (x0BlindingVar, genHVar)])
  # 2. 2. X1 = x1 * generatorH
  prover.Constrain(X1Var, [(x1Var, genHVar)])
  # 3. X2 = x2 * generatorH
  prover.Constrain(X2Var, [(x2Var, genHVar)])

  # 4. X0Aux = b * x0Blinding * generatorH
  # 4a. HAux = b * generatorH
  prover.Constrain(HAuxVar, [(bVar, genHVar)])
  # 4b: X0Aux = x0Blinding * HAux (= b * x0Blinding * generatorH)
  prover.Constrain(X0AuxVar, [(x0BlindingVar, HAuxVar)])

  #5. X1Aux = b * x1 * generatorH
  # 5a. X1Aux = b * X1 (X1 = x1 * generatorH)
  prover.Constrain(X1AuxVar, [(t1Var, genHVar)])
  # 5b. X1Aux = t1 * generatorH (t1 = b * x1)
  prover.Constrain(X1AuxVar, [(bVar, X1Var)])

  # 6. X2Aux = b * x2 * generatorH
  # 6a. X2Aux = b * X2 (X2 = x2 * generatorH)
  prover.Constrain(X2AuxVar, [(bVar, X2Var)])
  # 6b. X2Aux = t2 * H (t2 = b * x2)
  prover.Constrain(X2AuxVar, [(t2Var, genHVar)])

  # 7. U = b * generatorG
  prover.Constrain(UVar, [(bVar, genGVar)])
  # 8. encUPrime = b * (X0 + x1 * Enc(m1) + x2 * Enc(m2))
  # simplified: encUPrime = b * X0 + t1 * m1Enc + t2 * m2Enc, since t1 = b * x1 and t2 = b * x2
  prover.Constrain(encUPrimeVar, [(bVar, X0Var), (t1Var, m1EncVar), (t2Var, m2EncVar)])

  return prover.Prove()
~~~

### CredentialResponse Proof Verification

~~~
validity = VerifyCredentialResponseProof(serverPublicKey, response, request)

Inputs:
- serverPublicKey:
  - X0: Element, server public key 0.
  - X1: Element, server public key 1.
  - X2: Element, server public key 2.
- response:
  - U: Element, a randomized generator for the response. `b*G`.
  - encUPrime: Element, encrypted UPrime.
  - X0Aux: Element, auxiliary point for X0.
  - X1Aux: Element, auxiliary point for X1.
  - X2Aux: Element, auxiliary point for X2.
  - HAux: Element, auxiliary point for generatorH.
  - responseProof: ZKProof, a proof of correct generation of U, encUPrime, server public keys, and auxiliary points.
    - challenge: Scalar, the challenge used in the proof of valid response.
    - response0: Scalar, the response corresponding to x0.
    - response1: Scalar, the response corresponding to x1.
    - response2: Scalar, the response corresponding to x2.
    - response3: Scalar, the response corresponding to x0Blinding.
    - response4: Scalar, the response corresponding to b.
    - response5: Scalar, the response corresponding to t1.
    - response6: Scalar, the response corresponding to t2.
- request:
  - m1Enc: Element, first encrypted secret.
  - m2Enc: Element, second encrypted secret.
  - requestProof: ZKProof, a proof of correct generation of m1Enc and m2Enc.

Outputs:
- validity: Boolean, True if the proof verifies correctly, False otherwise.

Parameters:
- G: Group
- generatorG: Element, equivalent to G.GeneratorG()
- generatorH: Element, equivalent to G.GeneratorH()

def VerifyCredentialResponseProof(serverPublicKey, response, request):
  verifier = Verifier(contextString + "CredentialResponse")

  x0Var = verifier.AppendScalar("x0")
  x1Var = verifier.AppendScalar("x1")
  x2Var = verifier.AppendScalar("x2")
  x0BlindingVar = verifier.AppendScalar("x0Blinding")
  bVar = verifier.AppendScalar("b", b)
  t1Var = verifier.AppendScalar("t1")
  t2Var = verifier.AppendScalar("t2")

  genGVar = verifier.AppendElement("genG", generatorG)
  genHVar = verifier.AppendElement("genH", generatorH)
  m1EncVar = verifier.AppendElement("m1Enc", request.m1Enc)
  m2EncVar = verifier.AppendElement("m2Enc", request.m2Enc)
  UVar = verifier.AppendElement("U", response.U)
  encUPrimeVar = verifier.AppendElement("encUPrime", response.encUPrime)
  X0Var = verifier.AppendElement("X0", serverPublicKey.X0)
  X1Var = verifier.AppendElement("X1", serverPublicKey.X1)
  X2Var = verifier.AppendElement("X2", serverPublicKey.X2)
  X0AuxVar = verifier.AppendElement("X0Aux", response.X0Aux)
  X1AuxVar = verifier.AppendElement("X1Aux", response.X1Aux)
  X2AuxVar = verifier.AppendElement("X2Aux", response.X2Aux)
  HAuxVar = verifier.AppendElement("HAux", response.HAux)

  # 1. X0 = x0 * generatorG + x0Blinding * generatorH
  verifier.Constrain(X0Var, [(x0Var, genGVar), (x0BlindingVar, genHVar)])
  # 2. 2. X1 = x1 * generatorH
  verifier.Constrain(X1Var, [(x1Var, genHVar)])
  # 3. X2 = x2 * generatorH
  verifier.Constrain(X2Var, [(x2Var, genHVar)])

  # 4. X0Aux = b * x0Blinding * generatorH
  # 4a. HAux = b * generatorH
  verifier.Constrain(HAuxVar, [(bVar, genHVar)])
  # 4b: X0Aux = x0Blinding * HAux (= b * x0Blinding * generatorH)
  verifier.Constrain(X0AuxVar, [(x0BlindingVar, HAuxVar)])

  #5. X1Aux = b * x1 * generatorH
  # 5a. X1Aux = b * X1 (X1 = x1 * generatorH)
  verifier.Constrain(X1AuxVar, [(t1Var, genHVar)])
  # 5b. X1Aux = t1 * generatorH (t1 = b * x1)
  verifier.Constrain(X1AuxVar, [(bVar, X1Var)])

  # 6. X2Aux = b * x2 * generatorH
  # 6a. X2Aux = b * X2 (X2 = x2 * generatorH)
  verifier.Constrain(X2AuxVar, [(bVar, X2Var)])
  # 6b. X2Aux = t2 * H (t2 = b * x2)
  verifier.Constrain(X2AuxVar, [(t2Var, genHVar)])

  # 7. U = b * generatorG
  verifier.Constrain(UVar, [(bVar, genGVar)])
  # 8. encUPrime = b * (X0 + x1 * Enc(m1) + x2 * Enc(m2))
  # simplified: encUPrime = b * X0 + t1 * m1Enc + t2 * m2Enc, since t1 = b * x1 and t2 = b * x2
  verifier.Constrain(encUPrimeVar, [(bVar, X0Var), (t1Var, m1EncVar), (t2Var, m2EncVar)])

  return verifier.Verify(response.proof)
~~~

## Presentation Proof {#presentation-proof}

The presentation proof is a proof of knowledge of (m1, r, z) used in the presentation, and a proof that the counter used to make the tag is in the range of [0, rateLimit).

Statements to prove:

~~~
1. m1Commit = m1 * U + z * generatorH
2. V = z * X1 - r * generatorG
3. G.HashToGroup(presentationContext, "Tag") = m1 * tag + counter * tag
4. m1Tag = m1 * tag
~~~

### Presentation Proof Creation

~~~
presentationProof = MakePresentationProof(U, UPrimeCommit, m1Commit, tag, generatorT, credential, V, r, z, nonce, m1Tag)

Inputs:
- U: Element, re-randomized from the U in the response.
- UPrimeCommit: Element, a public key to the MACGGM output UPrime.
- m1Commit: Element, a public key to the client secret (m1).
- tag: Element, the tag element used for enforcing rate limiting and reuse.
- generatorT: Element, used for presentation tag computation.
- credential:
  - m1: Scalar, client's first secret.
  - U: Element, a randomized generator for the response. `b*G`.
  - UPrime: Element, the MAC over the server's private keys and the client's secrets.
  - X1: Element, server public key 1.
- V: Element, a proof helper element.
- r: Scalar (private), a randomly generated element used in presentation.
- z: Scalar (private), a randomly generated element used in presentation.
- nonce: Int, the nonce associated with the presentation.
- m1Tag: Element, helper element for the proof.

Outputs:
- proof: ZKProof
  - challenge: Scalar, the challenge used in the proof of valid presentation.
  - response0: Scalar, the response corresponding to m1.
  - response1: Scalar, the response corresponding to z.
  - response2: Scalar, the response corresponding to -r.
  - response3: Scalar, the response corresponding to nonce.

Parameters:
- G: Group
- generatorG: Element, equivalent to G.GeneratorG()
- generatorH: Element, equivalent to G.GeneratorH()
- contextString: public input

def MakePresentationProof(U, UPrimeCommit, m1Commit, tag, generatorT, presentationContext, credential, V, r, z, nonce, m1Tag)
  prover = Prover(contextString + "PresentationProof")

  m1Var = prover.AppendScalar("m1", credential.m1)
  zVar = prover.AppendScalar("z", z)
  rNegVar = prover.AppendScalar("-r", -r)
  nonceVar = prover.AppendScalar("nonce", nonce)

  genGVar = prover.AppendElement("genG", generatorG)
  genHVar = prover.AppendElement("genH", generatorH)
  UVar = prover.AppendElement("U", U)
  _ = prover.AppendElement("UPrimeCommit", UPrimeCommit)
  m1CommitVar = prover.AppendElement("m1Commit", m1Commit)
  VVar = prover.AppendElement("V", V)
  X1Var = prover.AppendElement("X1", credential.X1)
  tagVar = prover.AppendElement("tag", tag)
  genTVar = prover.AppendElement("genT", generatorT)
  m1TagVar = prover.AppendElement("m1Tag", m1Tag)

  # 1. m1Commit = m1 * U + z * generatorH
  prover.Constrain(m1CommitVar, [(m1Var, UVar), (zVar, genHVar)])
  # 2. V = z * X1 - r * generatorG
  prover.Constrain(VVar, [(zVar, X1Var), (rNegVar, genGVar)])
  # 3. G.HashToGroup(presentationContext, "Tag") = m1 * tag + counter * tag
  prover.Constrain(genTVar, [(m1Var, tagVar), (nonceVar, tagVar)])
  # 4. m1Tag = m1 * tag
  prover.Constrain(m1TagVar, [(m1Var, tagVar)])

  return prover.Prove()
~~~

### Presentation Proof Verification

~~~
validity = VerifyPresentationProof(serverPrivateKey, serverPublicKey, requestContext, presentationContext, presentation, m1Tag)

Inputs:
- serverPrivateKey:
  - x0: Scalar (private), server private key 0.
  - x1: Scalar (private), server private key 1.
  - x2: Scalar (private), server private key 2.
  - x0Blinding: Scalar (private), blinding value for x0.
- serverPublicKey:
  - X0: Element, server public key 0.
  - X1: Element, server public key 1.
  - X2: Element, server public key 2.
- requestContext: Data, context for the credential request.
- presentationContext: Data (public), used for presentation tag computation.
- presentation:
  - U: Element, re-randomized from the U in the response.
  - UPrimeCommit: Element, a public key to the issued UPrime.
  - m1Commit: Element, a public key to the client secret (m1).
  - tag: Element, the tag element used for enforcing rate limiting and reuse.
  - presentationProof: ZKProof, a proof of correct generation of the presentation.
    - challenge: Scalar, the challenge used in the proof of valid presentation.
    - response0: Scalar, the response corresponding to m1.
    - response1: Scalar, the response corresponding to z.
    - response2: Scalar, the response corresponding to -r.
    - response3: Scalar, the response corresponding to nonce.
- m1Tag: Element, helper to validate the presentation proof.

Outputs:
- validity: Boolean, True if the proof verifies correctly, False otherwise.

Parameters:
- G: Group
- generatorG: Element, equivalent to G.GeneratorG()
- generatorH: Element, equivalent to G.GeneratorH()
- contextString: public input

def VerifyPresentationProof(serverPrivateKey, serverPublicKey, requestContext, presentationContext, presentation, m1Tag):
  m2 = G.HashToScalar(requestContext, "requestContext")
  V = serverPrivateKey.x0 * presentation.U + serverPrivateKey.x1 * presentation.m1Commit + serverPrivateKey.x2 * m2 * presentation.U - presentation.UPrimeCommit
  generatorT = G.HashToGroup(presentationContext, "Tag")

  verifier = Verifier(contextString + "PresentationProof")

  m1Var = verifier.AppendScalar("m1")
  zVar = verifier.AppendScalar("z")
  rNegVar = verifier.AppendScalar("-r")
  nonceVar = verifier.AppendScalar("nonce")

  genGVar = verifier.AppendElement("genG", generatorG)
  genHVar = verifier.AppendElement("genH", generatorH)
  UVar = verifier.AppendElement("U", presentation.U)
  _ = verifier.AppendElement("UPrimeCommit", presentation.UPrimeCommit)
  m1CommitVar = verifier.AppendElement("m1Commit", presentation.m1Commit)
  VVar = verifier.AppendElement("V", presentation.V)
  X1Var = verifier.AppendElement("X1", serverPublicKey.X1)
  tagVar = prover.AppendElement("tag", presentation.tag)
  genTVar = verifier.AppendElement("genT", generatorT)
  m1TagVar = prover.AppendElement("m1Tag", m1Tag)

  # 1. m1Commit = m1 * U + z * generatorH
  verifier.Constrain(m1CommitVar, [(m1Var, UVar), (zVar, genHVar)])
  # 2. V = z * X1 - r * generatorG
  verifier.Constrain(VVar, [(zVar, X1Var), (rNegVar, genGVar)])
  # 3. G.HashToGroup(presentationContext, "Tag") = m1 * tag + nonceVar * tag
  verifier.Constrain(genTVar, [(m1Var, tagVar), (nonceVar, tagVar)])
  # 4. m1Tag = m1 * tag
  prover.Constrain(m1TagVar, [(m1Var, tagVar)])

  return verifier.Verify(presentation.proof)
~~~

# Ciphersuites {#ciphersuites}

A ciphersuite (also referred to as 'suite' in this document) for the protocol
wraps the functionality required for the protocol to take place. The
ciphersuite should be available to both the client and server, and agreement
on the specific instantiation is assumed throughout.

A ciphersuite contains an instantiation of the following functionality:

- `Group`: A prime-order Group exposing the API detailed in {{pog}}, with the
  generator element defined in the corresponding reference for each group. Each
  group also specifies HashToGroup, HashToScalar, and serialization functionalities.
  For HashToGroup, the domain separation tag (DST) is constructed in accordance
  with the recommendations in {{!I-D.irtf-cfrg-hash-to-curve, Section 3.1}}.
  For HashToScalar, each group specifies an integer order that is used in
  reducing integer values to a member of the corresponding scalar field.

This section includes an initial set of ciphersuites with supported groups.
It also includes implementation details for each ciphersuite, focusing on input validation.

## ARC(P-384)

This ciphersuite uses P-384 {{NISTCurves}} for the Group.
The value of the ciphersuite identifier is "P384". The value of
contextString is "ARCV1-P384".

- Group: P-256 (secp256r1) {{NISTCurves}}
  - Order(): Return 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551.
  - Identity(): As defined in {{NISTCurves}}.
  - Generator(): As defined in {{NISTCurves}}.
  - RandomScalar(): Implemented by returning a uniformly random Scalar in the range
    \[0, `G.Order()` - 1\]. Refer to {{random-scalar}} for implementation guidance.
  - HashToGroup(x, info): Use hash_to_curve with suite P384_XMD:SHA-384_SSWU_RO\_
    {{!I-D.irtf-cfrg-hash-to-curve}}, input `x`, and DST =
    "HashToGroup-" || contextString || info.
  - HashToScalar(x, info): Use hash_to_field from {{!I-D.irtf-cfrg-hash-to-curve}}
    using L = 72, `expand_message_xmd` with SHA-384, input `x` and
    DST = "HashToScalar-" || contextString || info, and
    prime modulus equal to `Group.Order()`.
  - ScalarInverse(s): Returns the multiplicative inverse of input Scalar `s` mod `Group.Order()`.
  - SerializeElement(A): Implemented using the compressed Elliptic-Curve-Point-to-Octet-String
    method according to {{SEC1}}; Ne = 49.
  - DeserializeElement(buf): Implemented by attempting to deserialize a 49-byte array  to
    a public key using the compressed Octet-String-to-Elliptic-Curve-Point method according to {{SEC1}},
    and then performs partial public-key validation as defined in section 5.6.2.3.4 of
    {{!KEYAGREEMENT=DOI.10.6028/NIST.SP.800-56Ar3}}. This includes checking that the
    coordinates of the resulting point are in the correct range, that the point is on
    the curve, and that the point is not the point at infinity. Additionally, this function
    validates that the resulting element is not the group identity element.
    If these checks fail, deserialization returns an InputValidationError error.
  - SerializeScalar(s): Implemented using the Field-Element-to-Octet-String conversion
    according to {{SEC1}}; Ns = 48.
  - DeserializeScalar(buf): Implemented by attempting to deserialize a Scalar from a 48-byte
    string using Octet-String-to-Field-Element from {{SEC1}}. This function can fail if the
    input does not represent a Scalar in the range \[0, `G.Order()` - 1\].

## Random Scalar Generation {#random-scalar}

Two popular algorithms for generating a random integer uniformly distributed in
the range \[0, G.Order() -1\] are as follows:

### Rejection Sampling

Generate a random byte array with `Ns` bytes, and attempt to map to a Scalar
by calling `DeserializeScalar` in constant time. If it succeeds, return the
result. If it fails, try again with another random byte array, until the
procedure succeeds. Failure to implement `DeserializeScalar` in constant time
can leak information about the underlying corresponding Scalar.

As an optimization, if the group order is very close to a power of
2, it is acceptable to omit the rejection test completely.  In
particular, if the group order is p, and there is an integer b
such that |p - 2<sup>b</sup>| is less than 2<sup>(b/2)</sup>, then
`RandomScalar` can simply return a uniformly random integer of at
most b bits.

### Random Number Generation Using Extra Random Bits

Generate a random byte array with `L = ceil(((3 * ceil(log2(G.Order()))) / 2) / 8)`
bytes, and interpret it as an integer; reduce the integer modulo `G.Order()` and return the
result. See {{I-D.irtf-cfrg-hash-to-curve, Section 5}} for the underlying derivation of `L`.

# Security Considerations

For arguments about correctness, unforgeability, anonymity, and blind issuance of the ARC protocol, see the
"Formal Security Definitions for Keyed-Verification Anonymous Credentials" in {{KVAC}}.

This section elaborates on unlinkability properties for ARC and other implementation details
necessary for these properties to hold.

## Credential Issuance Unlinkability

Client credential requests are constructed such that the server cannot distinguish between any two credential requests from the same client and two requests from different clients. We refer to this property as issuance unlinkability. This property is achieved by the way the credential requests are constructed. In particular, each credential request consists of two Pedersen commitments with fresh blinding factors, which are used to commit to a freshly generated client secret and request context. The resulting request is therefore perfetly hiding, and independent from other requests from the same client. More details about this unlinkability property can be found in {{KVAC}} and {{REVISITING_KVAC}}.

## Presentation Unlinkability {#pres-unlinkability}

Client credential presentations are constructed so that all presentations are indistinguishable, even if coming from the same user. We refer to this property as presentation unlinkability. This property is achieved by the way the credential presentations are constructed. The presentation elements `[U, UPrimeCommit, m1Commit]` are indistinguishable from all other presentations made from credentials issued with the same server keys, as detailed in {{KVAC}}.

The indistinguishability set for these presentation elements is `sum_{i=0}^c(p_i)`, where `c` is the number of credentials issued with the same server keys, and `p_i` is the number of presentations made for each of those credentials.

The presentation elements `[tag, nonce, presentationContext, presentationProof]` are indistinguishable from all presentations made from credentials issued with the same server keys for that presentationContext, with the exception of presentations with the same nonce (since those presentations can be ascertained as being generated from different credentials, as long as the presentation tag is unique).

The indistinguishability set for those presentation elements is `sum_{i=0}^c(p_i[presentationContext]) - k[presentationContext]`, where `c` is the number of credentials issued with the same server keys, `p_i[presentationContext]` is the number of presentations made for each of those credentials with the same presentationContext, and `k` is the number of presentations with the same nonce for that presentationContext. As long as the nonces are generated randomly from the range defined by the rate limit, `k[presentationContext]` should be roughly equal to `sum_{i=0}^c(p_i[presentationContext]) / n`, where `n` is the rate limit. Therefore, the indistinguishability set can be represented as `sum_{i=0}^c(p_i[presentationContext])(1 - 1/n)`, where a larger rate limit results in a larger indistinguishability set and therefore stronger unlinkability properties.

[[OPEN ISSUE: hide the nonce and replace the tag proof with a range proof built from something like Bulletproofs.]]

## Timing Leaks

To ensure no information is leaked during protocol execution, all operations that use secret data MUST run in constant time. This includes all prime-order group operations and proof-specific operations that operate on secret data, including proof generation and verification.

# Alternatives considered

## Alternative Algebraic MACs

ARC uses the MACGGM algebraic MAC as its underlying primitive, as detailed in {{KVAC}} and {{REVISITING_KVAC}}. This offers the benefit of having a lower credential size than MACDDH, which is an alternative algebraic MAC detailed in {{KVAC}}.

The BBS anonymous credential scheme, as detailed in {{BBS}} and its variants, is efficient and publicly verifiable, but requires pairings for verification. This is problematic for adoption because pairings are complex to implement securely, and aren't supported as widely in software and hardware as non-pairing elliptic curves.

It is possible to construct a keyed-verification variant of BBS which doesn't use pairings, as discussed in {{BBDT17}} and {{REVISITING_KVAC}}. However these keyed-verification BBS variants require more analysis, proofs of security properties, and review to be considered mature enough for standardization.

# IANA Considerations

This document has no IANA actions.

# Test Vectors

This section contains test vectors for the ARC ciphersuites specified in this document.

{::include ./poc/vectors/allVectors.txt}

# Acknowledgments

The authors would like to acknowledge helpful conversations with Tommy Pauly about rate limiting and Privacy Pass integration.

--- back

