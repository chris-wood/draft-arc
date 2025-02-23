---
title: "Privacy Pass Issuance Protocol for Anonymous Rate-Limited Credentials"
abbrev: "Privacy Pass Issuance Protocol for ARC"
category: std

docname: draft-yun-privacypass-arc-latest
submissiontype: IETF
consensus: true
number:
date:
v: 3
venue:
  group: PRIVACYPASS
  type: Privacy Pass
  mail: WG@example.com
  arch: https://example.com/WG
  github: USER/REPO
  latest: https://example.com/LATEST

author:
 -
    ins: C. Yun
    name: Cathie Yun
    organization: Apple, Inc.
    email: cathieyun@gmail.com
 -
    ins: C. A. Wood
    name: Christopher A. Wood
    org: Apple, Inc.
    email: caw@heapingbits.net

normative:
  ARC: I-D.draft-yun-cfrg-arc-00
  ARCHITECTURE: RFC9576
  AUTHSCHEME: RFC9577
  ISSUANCE: RFC9578

informative:

--- abstract

This document specifies the issuance and redemption protocols for
tokens based on the Anonymous Rate-Limited Credential (ARC) protocol.

--- middle

# Introduction

{{ARCHITECTURE}} describes the Privacy Pass architecture, and {{ISSUANCE}}
and {{AUTHSCHEME}} describe the issuance and redemption protocols for
basic Privacy Pass tokens, i.e., those computed using blind RSA signatures
(as specified in {{!BLIND-RSA=RFC9474}}) or verifiable oblivious
pseudorandom functions (as specified in {{!VOPRFS=RFC9497}}). These protocols
are widely deployed in practice for a variety of applications, including
anonymous authentication for protocols such as Oblivious HTTP {{?OHTTP=RFC9458}}
and the Distributed Aggregation Protocol {{?DAP=I-D.ietf-ppm-dap}}. While
effective, these variants of Privacy Pass tokens are limited in that
each token can only be spent once. These are often calle "one-time-use" tokens.
This means that applications which wish to limit access to a given user, e.g.,
for the purposes of throttling or rate limiting them, must issue one token
for each redemption.

The Anonymous Rate-Limited Credential (ARC) protocol, as specified in {{ARC}},
offers a more scalable approach to rate limiting. In particular, ARC credentials
can be issued once and then presented (or redeemed) up to some fixed-amount
of time for distinct, per-origin presentation contexts. This means that a Client
will only be able to present a limited number of tokens associated with a given
context.

This document specifies the issuance and redemption protocols for ARC. {{motivation}}
describes motivation for this new type of token, {{overview}} presents an overview
of the protocols, and the remainder of the document specifies the protocols themselves.

# Motivation

To demonstrate how ARC is useful, consider the case where a client wishes to keep
its IP address private while accessing a service. The client can hide its IP
address using a proxy service or a VPN. However, doing so severely limits the
client's ability to access services and content, since servers might not be able
to enforce their policies without a stable and unique client identifier.

With one-time-use tokens, the server can verify that each client access meets
a particular bar for attestation, i.e., the bar that is enforced during issuance,
but cannot be used by the server to rate limit a specific client. This is because
there is no mechanism in the issuance protocol to link repeated Client token
requests in order to apply rate-limiting.

There are several use cases for rate-limiting anonymous clients that are common
on the Internet. These routinely use client IP address tracking, among other
characteristics, to implement rate-limiting.

One example of this use case is rate-limiting website accesses to a client to
help prevent abusive behavior. Operations that are sensitive to abuse, such as
account creation on a website or logging into an account, often employ rate-limiting
as a defense-in-depth strategy. Additional verification can be required by these
pages when a client exceeds a set rate-limit.

# Terminology

{::boilerplate bcp14-tagged}

This document uses the terms Origin, Client, Issuer, and Token as defined in
{{Section 2 of ARCHITECTURE}}. Moreover, the following additional terms are
used throughout this document.

- Issuer Public Key: The public key (from a private-public key pair) used by
  the Issuer for issuing and verifying Tokens.
- Issuer Private Key: The private key (from a private-public key pair) used by
  the Issuer for issuing and verifying Tokens.

Unless otherwise specified, this document encodes protocol messages in TLS
notation from {{Section 3 of !TLS13=RFC8446}}. Moreover, all constants are in
network byte order.

# Protocol Overview {#overview}

The issuance and redemption protocols defined in this document are built on
the Anonymous Rate-Limited Credential (ARC) protocol. In contrast to the core
Privacy Pass protocols which are one-time-use anonymous credentials, ARC allows
clients to turn a single credential output from an issuance protocol into a
fixed number of unlinkable tokens, each of which are bound to some agreed-upon
public presentation context.

With ARC, Clients receive TokenChallenge inputs from the redemption protocol
({{AUTHSCHEME, Section 2.1}}). If they have a valid credential for the designated
Issuer, Clients can use the TokenChallenge to produce a single token for
presentation. Otherwise, Clients invoke the issuance protocol to obtain a
credential. This interaction is shown below.

~~~ aasvg
                                      +---------------------------+
+--------+          +----------+      |  +--------+   +--------+  |
| Client |          | Attester |      |  | Issuer |   | Origin |  |
+---+----+          +-----+----+      |  +----+---+   +---+----+  |
    |                     |           +-------|-----------|------ +
    |                     |                   |           |
    |--------------------- Request ---------------------->|
    <----------------- TokenChallenge --------------------+
    |                     |                   |           |
    | <== Attestation ==> |                   |           |
    +----------- CredentialRequest ---------->|           |
    |<---------- CredentialResponse ----------+           |
    |                     |                   |           |
    |----------- Request + Token ------------------------>|
    |                     |                   |           |
~~~
{: #fig-overview title="Issuance and Redemption Overview"}

Similar to the core Privacy Pass protocols, the TokenChallenge can
be interactive or non-interactive, and per-origin or cross-origin.

ARC is only compatible with deployment models where the Issuer and Origin
are operated by the same entity (see {{Section 4 of ARCHITECTURE}}), as
tokens produced from a credential are not publicly verifiable. The details
of attestation are outside the scope of the issuance protocol; see
{{Section 4 of ARCHITECTURE}} for information about how attestation can
be implemented in each of the relevant deployment models.

The issuance and redemption protocols in this document are built on
{{ARC}}.

# Configuration {#setup}

ARC Issuers are configured with key material used for issuance and token
verification. Concretely, Issuers run the `SetupServer` function from {{ARC}}
to produce a private and public key, denoted skI and pkI, respectively.

~~~
skI, pkI = SetupServer()
~~~

The Issuer Public Key ID, denoted `issuer_key_id`, is computed as the
SHA-256 hash of the Issuer Public Key, i.e., `issuer_key_id = SHA-256(pkI_serialized)`,
where `pkI_serialized` is the serialized version of `pkI` as described in [Section 4.1 of ARC].

# Token Challenge Requirements {#token-challenge-requirements}

Clients receive challenges for tokens as described in {{AUTHSCHEME}}.
The HTTP authentication challenge also SHOULD contain the following
additional attribute:

- "rate-limit", which contains a JSON number indicating the presentation
  limit to use for ARC.

# Credential Issuance Protocol

Issuers provide an Issuer Private and Public Key, denoted `skI` and `pkI`
respectively, used to produce tokens as input to the protocol. See {{setup}}
for how these keys are generated.

Clients provide the following as input to the issuance protocol:

- Issuer Request URL: A URL identifying the location to which issuance requests
  are sent. This can be a URL derived from the "issuer-request-uri" value in the
  Issuer's directory resource, or it can be another Client-configured URL. The value
  of this parameter depends on the Client configuration and deployment model.
  For example, in the 'Joint Origin and Issuer' deployment model, the Issuer
  Request URL might correspond to the Client's configured Attester, and the
  Attester is configured to relay requests to the Issuer.
- Issuer name: An identifier for the Issuer. This is typically a host name that
  can be used to construct HTTP requests to the Issuer.
- Issuer Public Key: `pkI`, with a key identifier `token_key_id` computed as
  described in {{setup}}.

Given this configuration and these inputs, the two messages exchanged in
this protocol to produce a credential are described below.

## Client-to-Issuer Request

Given Origin-provided input `tokenChallenge` and the Issuer Public Key ID `issuer_key_id`,
the Client first creates a credential request message using the `CredentialRequest`
function from {{ARC}} as follows:

~~~
request_context = concat(tokenChallenge.issuer_name, issuer_key_id)
(clientSecrets, request) = CredentialRequest(request_context)
~~~

The Client then creates a TokenRequest structure as follows:

~~~
struct {
  uint16_t token_type = 0xC7D3; /* Type ARC(P-384) */
  uint8_t truncated_issuer_key_id;
  uint8_t encoded_request[Nrequest];
} TokenRequest;
~~~

The structure fields are defined as follows:

- "token_type" is a 2-octet integer.

- "truncated_issuer_key_id" is the least significant byte of the `issuer_key_id`
  ({{setup}}) in network byte order (in other words, the last 8
  bits of `issuer_key_id`). This value is truncated so that Issuers cannot use
  `issuer_key_id` as a way of uniquely identifying Clients; see {{security}}
  and referenced information for more details.

- "encoded_request" is the Nrequest-octet request, computed as the serialization
  of the `request` value as defined in [Section 4.2.1 of ARC].

The Client then generates an HTTP POST request to send to the Issuer Request URL,
with the TokenRequest as the content. The media type for this request is
"application/private-credential-request". An example request for the Issuer Request URL
"https://issuer.example.net/request" is shown below.

~~~
POST /request HTTP/1.1
Host: issuer.example.net
Accept: application/private-credential-response
Content-Type: application/private-credential-request
Content-Length: <Length of TokenRequest>

<Bytes containing the TokenRequest>
~~~

## Issuer-to-Client Request

Upon receipt of the request, the Issuer validates the following conditions:

- The TokenRequest contains a supported token_type equal to value 0xC7D3.
- The TokenRequest.truncated_token_key_id corresponds to the truncated key ID
  of an Issuer Public Key, with corresponding secret key `skI`, owned by
  the Issuer.
- The TokenRequest.encoded_request is of the correct size (`Nrequest`).

If any of these conditions is not met, the Issuer MUST return an HTTP 422
(Unprocessable Content) error to the client.

If these conditions are met, the Issuer then tries to deserialize
TokenRequest.encoded_request according to [Section 4.2.1 of ARC], yielding `request`.
If this fails, the Issuer MUST return an HTTP 422 (Unprocessable Content)
error to the client. Otherwise, if the Issuer is willing to produce a credential
for the Client, the Issuer completes the issuance flow by an issuance response
as follows:

~~~
response = CredentialResponse(skI, pkI, request)
~~~

The Issuer then creates a TokenResponse structured as follows:

~~~
struct {
   uint8_t encoded_response[Nresponse];
} TokenResponse;
~~~

The structure fields are defined as follows:

- "encoded_response" is the Nresponse-octet encoded issuance response message, computed
  as the serialization of `response` as specified in [Section 4.2.2 of ARC].

The Issuer generates an HTTP response with status code 200 whose content
consists of TokenResponse, with the content type set as
"application/private-credential-response".

~~~
HTTP/1.1 200 OK
Content-Type: application/private-credential-response
Content-Length: <Length of TokenResponse>

<Bytes containing the TokenResponse>
~~~

## Credential Finalization

Upon receipt, the Client handles the response and, if successful, deserializes
the content values `TokenResponse.encoded_response` according to [Section 4.2.2 of ARC]
yielding `response`. If deserialization fails, the Client aborts the protocol.
Otherwise, the Client processes the response as follows:

~~~
credential = FinalizeCredential(clientSecrets, pkI, request, response)
~~~

The Client then saves the credential structure, associated with the given Issuer
Name, to use when producing Token values in response to future token challenges.

# Token Redemption Protocol

The token redemption protocol takes as input TokenChallenge and presentation limit
values from {{AUTHSCHEME, Section 2.1}}; the presentation limit is sent as an additional
attribute within the HTTP challenge as described in {{token-challenge-requirements}}.
Clients use credentials from the issuance protocol in producing tokens
bound to the TokenChallenge. The process for producing a token in this
way, as well as verifying a resulting token, is described in the following sections.

## Token Creation

Given a TokenChallenge value as input, denoted `challenge`, a presentation limit,
denoted `presentationLimit`, and a previously computed credential that is valid
for the Issuer identifier in the challenge, denoted `credential`, Clients compute
a credential presentation value as follows:

~~~
presentation_context = concat(challenge_digest, issuer_key_id)
state = MakePresentationState(credential, presentation_context, presentationLimit)
newState, nonce, presentation = Present(state)
~~~

Subsequent presentations MUST use the updated state, denoted `newState`. Reusing
the original state will break the presentation unlinkability properties of ARC;
see {{security}}.

The resulting Token value is then constructed as follows:

~~~
struct {
    uint16_t token_type = 0xC7D3; /* Type ARC(P-384) */
    uint8_t issuer_key_id[Nid];
    uint32_t presentation_nonce;
    uint8_t presentation[Npresentation];
} Token;
~~~

The structure fields are defined as follows:

- "token_type" is a 2-octet integer, in network byte order, equal to 0xC7D3.

- "issuer_key_id" is a Nid-octet identifier for the Issuer Public Key, computed
as defined in {{setup}}.

- "presentation_nonce" is a 32-bit encoding of the nonce output from ARC.

- "presentation" is a Npresentation-octet presentation, set to the serialized
`presentation` value (see [Section 4.3.2 of ARC] for serialiation details).

## Token Verification {#verification}

Given a deserialized presentation from the token, denoted `presentation` and
obtained by deserializing a presentation according to [Section 4.3.2 of ARC],
a presentation limit, denoted `presentation_limit`, a presentation nonce
from a token, denoted `nonce`, and the digest of a token challenge, denoted
`challenge_digest`, verifying a Token requires invoking the VerifyPresentation
function from [Section 4.3.3 of ARC] in the following wayz:

~~~
request_context = concat(tokenChallenge.issuer_name, issuer_key_id)
presentation_context = concat(challenge_digest, issuer_key_id)
valid = VerifyPresentation(skI, pkI, request_context, presentation_context, nonce, presentation, presentation_limit)
~~~

This function returns True if the CredentialToken is valid, and False otherwise.

# Security Considerations {#security}

Privacy considerations for tokens based on deployment details, such as issuer configuration
and issuer selection, are discussed in {{Section 6.1 of ARCHITECTURE}}. Note that ARC
requires a joint Origin and Issuer configuration given that it is privately verifiable.

ARC offers Origin-Client unlinkability, Issuer-Client unlinkability, and redemption context
unlinkability, as described in {{Section 3.3 of ARCHITECTURE}}, with one exception.
While redemption context unlinkability is achieved by re-randomizing credentials every time
they are presented as tokens, there is a reduction in the anonymity set in the case of presentation
nonce collisions, as detailed in {{Section 7.2 of AUTHSCHEME}}.

# IANA Considerations

This document updates the "Privacy Pass Token Type" Registry with the
following entries.

* Value: 0xC7D3
* Name: ARC (P-384)
* Token Structure: As defined in {{Section 2.2 of AUTHSCHEME}}
* Token Key Encoding: Serialized as described in {{setup}}
* TokenChallenge Structure: As defined in {{Section 2.1 of AUTHSCHEME}}
* Public Verifiability: N
* Public Metadata: N
* Private Metadata: N
* Nk: 0 (not applicable)
* Nid: 32
* Reference: This document
* Notes: None


--- back

# Acknowledgments
{:numbered="false"}

The authors would like to thank Tommy Pauly and the authors
of {{?RATE-LIMITED=I-D.ietf-privacypass-rate-limit-tokens}}
for helpful discussions on rate-limited tokens.
