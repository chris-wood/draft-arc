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
    email: cathie@apple.com
 -
    ins: C. A. Wood
    name: Christopher A. Wood
    org: Apple, Inc.
    email: caw@heapingbits.net

normative:
  AUTHSCHEME: I-D.ietf-privacypass-auth-scheme
  ARCHITECTURE: I-D.ietf-privacypass-architecture

informative:

--- abstract

TODO Abstract


--- middle

# Introduction

TODO Introduction


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

# Protocol Overview

The issuance and redemption protocols defined in this document are built on
an anonymous credential construction called KVAC. In contrast to the core Privacy
Pass protocols which are one-time-use anonymous credentials, KVAC allows clients
to turn a single credential output from an issuance protocol into an arbitarary
number of unlinkable tokens.

With KVAC, Clients receive TokenChallenge inputs from the redemption protocol
({{AUTHSCHEME, Section 2.1}}). If they have a valid credential for the designated
Issuer, Clients can use the TokenChallenge to produce a single token for
presentation. Otherwise, Clients invoke the issuance protocol to obtain a
credential. This interaction is shown below.

~~~ aasvg
+--------+            +--------+         +----------+ +--------+
| Origin |            | Client |         | Attester | | Issuer |
+---+----+            +---+----+         +----+-----+ +---+----+
    |                     |                   |           |
    |<----- Request ------+                   |           |
    +-- TokenChallenge -->|                   |           |
    |                     |<== Attestation ==>|           |
    |                     |                   |           |
    |                     +------ CredentialRequest ----->|
    |                     |<---- CredentialResponse ------+
    |<-- Request+Token ---+                   |           |
    |                     |                   |           |
~~~
{: #fig-overview title="Issuance and Redemption Overview"}

Similar to the core Privacy Pass protocols, the TokenChallenge can
be interactive or non-interactive, and per-origin or cross-origin.
However, unlike the core Privacy Pass protocols, TokenChallenge values
are not inputs to the issuance protocol used for producing credentialsl;
they are only used for the redemption protocol.

KVAC is only compatible with deployment models where the Issuer and Origin
are operated by the same entity (see {{Section 4 of ARCHITECTURE}}), as
tokens produced from a credential are not publicly verifiable. The details
of attestation are outside the scope of the issuance protocol; see
{{Section 4 of ARCHITECTURE}} for information about how attestation can
be implemented in each of the relevant deployment models.

The issuance and redemption protocols in this document are built on
{{!KVAC-SPEC=I-D.yun-cfrg-kvac}}.

# Configuration {#setup}

KVAC issuers are configured with key material used for issuance and credential
verification. Concretely, Issuers run the `SetupServer` function from {{KVAC-SPEC}}
to produce three secret keys and two public keys, as follows:

~~~
skI = SetupServer()
~~~

The Issuer Secret Key is the output of SetupServer.
The Issuer Public Key is `pkI = skI.PublicKey()`, where `PublicKey`
is as defined in {{KVAC-SPEC}}. The Issuer Public Key ID, denoted
`issuer_key_id`, is computed as the SHA-256 hash of the Issuer Public
Key, i.e., `issuer_key_id = SHA-256(pkI)`.

# Credential Issuance Protocol

Issuers provide a Issuer Private and Public Key, denoted `skI` and `pkI` respectively,
used to produce tokens as input to the protocol. See {{setup}}
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

Given Origin-provided input `tokenChallenge`, Issuer Public Key ID `issuer_key_id`,
and the resulting `challenge_digest` from the token challenge, the Client first
creates a credential request message using the `CredentialRequest` function from
{{KVAC-SPEC}} as follows:

~~~
presentation_context = concat(0xC7D3, challenge_digest, issuer_key_id)
(clientSecrets, request) = CredentialRequest(tokenChallenge)
~~~

The Client then creates a TokenRequest structure as follows:

~~~
struct {
  uint16_t token_type = 0xC7D3; /* Type KVAC(P-384, SHA-384) */
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
  of the `request` value as defined in {{KVAC-SPEC}}.

The Client then generates an HTTP POST request to send to the Issuer Request URL,
with the TokenRequest as the content. The media type for this request is
"application/private-token-request". An example request for the Issuer Request URL
"https://issuer.example.net/request" is shown below.

~~~
POST /request HTTP/1.1
Host: issuer.example.net
Accept: application/KVAC-response
Content-Type: application/KVAC-request
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
TokenRequest.encoded_request according to {{KVAC-SPEC}}, yielding `request`.
If this fails, the Issuer MUST return an HTTP 422 (Unprocessable Content)
error to the client. Otherwise, if the Issuer is willing to produce a credential
for the Client, the Issuer completes the issuance flow by an issuance response
as follows:

~~~
response = CredentialResponse(skI, request)
~~~

The Issuer then creates a TokenResponse structured as follows:

~~~
struct {
   uint8_t encoded_response[Nresponse];
} TokenResponse;
~~~

The structure fields are defined as follows:

- "encoded_response" is the Nresponse-octet encoded issuance response message, computed
  as the serialization of `response` as specified in {{KVAC-SPEC}}.

The Issuer generates an HTTP response with status code 200 whose content
consists of TokenResponse, with the content type set as
"application/private-token-response".

~~~
HTTP/1.1 200 OK
Content-Type: application/KVAC-response
Content-Length: <Length of TokenResponse>

<Bytes containing the TokenResponse>
~~~

## Credential Finalization

Upon receipt, the Client handles the response and, if successful, deserializes
the content values `TokenResponse.encoded_response` according to {{KVAC-SPEC}}
yielding `response`. If deserialization fails, the Client aborts the protocol.
Otherwise, the Client processes the response as follows:

~~~
credential = FinalizeCredential(clientSecrets, request, response)
~~~

The Client then saves the credential structure, associated with the given Issuer
Name, to use when producing Token values in response to future token challenges.

# Token Redemption Protocol

The token redemption protocol takes as input TokenChallenge values from
{{AUTHSCHEME, Section 2.1}} as well as arbitrary application context
information to produce a token. Clients use credentials from the issuance
protocol in producing tokens bound to these inputs. The process for producing
a token in this way, as well as verifying a resulting token, is described
in the following sections.

## Token Creation

Given a TokenChallenge value as input, denoted `challenge`, application contextual
information, denoted `context`, and a previously computed credential, denoted
`credential`, Clients compute a credential presentation value as follows:

~~~
presentation_context = concat(0xC7D3, challenge_digest, issuer_key_id)
presentation = Present(credential, presentation_context)
~~~

The resulting Token value is then constructed as follows:

~~~
struct {
    uint16_t token_type = 0xC7D3; /* Type KVAC(P-384, SHA-384) */
    uint8_t challenge_digest[32];
    uint8_t issuer_key_id[Nid];
    uint8_t credential_proof[Nproof];
} Token;
~~~

The structure fields are defined as follows:

- "token_type" is a 2-octet integer, in network byte order, equal to 0xC7D3.

- "challenge_digest" is a 32-octet value containing the hash of the
original TokenChallenge, SHA-256(TokenChallenge), where SHA-256 is as defined
in {{!SHS=DOI.10.6028/NIST.FIPS.180-4}}. Changing the hash function to something
other than SHA-256 would require defining a new token type and token structure
(since the contents of challenge_digest would be computed differently),
which can be done in a future specification.

- "issuer_key_id" is a Nid-octet identifier for the Issuer Public Key, computed
as defined in {{setup}}.

- "credential_proof" is a Nproof-octet presentation proof, set to the serialized `presentation`
value (see {{KVAC-SPEC}} for serialiation details) that is cryptographically bound
to the preceding fields in the token; see {{verification}} for more information
about how this field is used in verifying a token.

## Token Verification {#verification}

Verifying a Token requires invoking the VerifyPresentationProof
function from {{KVAC-SPEC}} in the following way:

~~~
presentation_context = concat(0xC7D3, challenge_digest, issuer_key_id)
valid = VerifyPresentationProof(serverSecrets, CredentialToken.credential_proof, presentation_context)
~~~

This function returns True if the CredentialToken is valid, and False otherwise.

# Security Considerations {#security}

TODO Security


# IANA Considerations

This document updates the "Privacy Pass Token Type" Registry with the
following entries.

* Value: 0xC7D3
* Name: KVAC (P-384, SHA-384)
* Token Structure: As defined in {{Section 2.2 of AUTHSCHEME}}
* Token Key Encoding: Serialized as described in {{setup}}
* TokenChallenge Structure: As defined in {{Section 2.1 of AUTHSCHEME}}
* Public Verifiability: N
* Public Metadata: N
* Private Metadata: N
* Nk: 48
* Nid: 32
* Reference: This document
* Notes: None


--- back

# Acknowledgments
{:numbered="false"}

TODO acknowledge.
