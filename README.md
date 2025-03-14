# Verifiable Credential Cryptosuite (ECDSA)

[![Release](https://github.com/herculas/vc-suite-ecdsa/actions/workflows/release.yml/badge.svg)](https://github.com/herculas/vc-suite-ecdsa/actions/workflows/release.yml)
[![JSR](https://jsr.io/badges/@herculas/vc-suite-ecdsa)](https://jsr.io/@herculas/vc-suite-ecdsa)
[![JSR Score](https://jsr.io/badges/@herculas/vc-suite-ecdsa/score)](https://jsr.io/@herculas/vc-suite-ecdsa)

ECDSA cryptographic suite for linked data files. This cryptosuite is compatible with the W3C specification of
[Verifiable Credentials Data Model](https://www.w3.org/TR/vc-data-model-2.0/),
[Verifiable Credential Data Integrity](https://www.w3.org/TR/vc-data-integrity/), and
[ECDSA Cryptosuites](https://www.w3.org/TR/vc-di-ecdsa/).

## Introduction

ECDSA signatures are specified in [NIST-FIPS-186-5](https://csrc.nist.gov/pubs/fips/186-5/final) with elliptic curve
P-256 and P-384 specified in [NIST-SP-800-186](https://csrc.nist.gov/pubs/sp/800/186/final). The elliptic curve P-256
and P-384 are respectively referred as secp256r1 and secp384r1 in [SEC2](http://www.secg.org/sec2-v2.pdf).

This cryptosuite implementation uses either the
[RDF Dataset Canonicalization Algorithm](https://www.w3.org/TR/rdf-canon/) or the
[JSON Canonicalization Scheme](https://datatracker.ietf.org/doc/html/rfc8785) to transform the input document into its
canonical form. It uses one of two mechanisms to digest and sign:
[SHA-256](https://datatracker.ietf.org/doc/html/rfc6234#autoid-5) as the message digest algorithm and ECDSA with Curve
P-256 as the signature algorithm, or [SHA-384](https://datatracker.ietf.org/doc/html/rfc6234#autoid-6) as the message
digest algorithm and ECDSA with Curve P-384 as the signature algorithm.

## Getting started

To use this cryptosuite, you need to install the package:

```bash
deno add jsr:@herculas/vc-data-integrity jsr:@herculas/vc-suite-ecdsa
```

## Usage

### Keypair operations

#### Generate and initialize keypair instances

Initialize an ECDSA keypair instance, and generate a keypair.

```typescript
import { ECKeypair } from "@herculas/vc-suite-ecdsa"

const keypair = new ECKeypair()
keypair.controller = "did:example:1145141919810"
await keypair.initialize()
```

#### Export keypair instances

You could export an ECDSA keypair instance to a JSON object called the _verification method_, which could further be
encapsulated into a controlled identifier document (e.g., a DID document).

```typescript
const method = await keypair.export({
  type: "JsonWebKey",
  flag: "private",
})
```

The `export()` method accepts an `options` object as parameter, which could specify the `type` and `flag` fields.

- The `type` field specifies the format of the exported keypair. The supported values are:

  - `JsonWebKey`: The keypair is exported as a JSON Web Key (JWK) object.
  - `Multikey`: The keypair is exported as a MultiKey object.

- The `flag` field specifies whether to export the private or public key. If the specified key is not present in the
  current keypair instance, an error will be raised.

Below is an example of the exported verification method containing a P-256 keypair in `Multikey` format:

```json
{
  "id": "did:key:zDnaepBuvsQ8cpsWrVKw8fbpGpvPeNSjVPTWoq6cRqaYzBKVP#zDnaepBuvsQ8cpsWrVKw8fbpGpvPeNSjVPTWoq6cRqaYzBKVP",
  "type": "Multikey",
  "controller": "did:key:zDnaepBuvsQ8cpsWrVKw8fbpGpvPeNSjVPTWoq6cRqaYzBKVP",
  "publicKeyMultibase": "zDnaepBuvsQ8cpsWrVKw8fbpGpvPeNSjVPTWoq6cRqaYzBKVP",
  "secretKeyMultibase": "z42twTcNeSYcnqg1FLuSFs2bsGH3ZqbRHFmvS9XMsYhjxvHN"
}
```

and a P-384 keypair in `JsonWebKey` format:

```json
{
  "id": "did:example:1145141919810#-ZfIG4j_rW58OTC8F4WIAMA7s4Ig81mvp1Yoiu6p5mY=",
  "type": "JsonWebKey",
  "controller": "did:example:1145141919810",
  "secretKeyJwk": {
    "kty": "EC",
    "use": "sig",
    "key_ops": ["sign"],
    "alg": "ES384",
    "ext": true,
    "crv": "P-384",
    "x": "sbcDneKt_Q4fImuyMtturQbz67Mf3Y79wmKv1A07r3FmbxJaN1tReSG8OMH2B-Ft",
    "y": "X4qf2gemrer8xJnzW4Rer2VmN11f8TkDyLRc8-XsfBMtvRvC8gyWEQ2IImnL8pAC",
    "d": "N-c2EJK-pH68ZmQYv4FRzHMgZBA0XKGz2F5u777FE3QCSW60FCKAWIIoaAi7JQre"
  },
  "publicKeyJwk": {
    "kty": "EC",
    "use": "sig",
    "key_ops": ["verify"],
    "alg": "ES384",
    "ext": true,
    "crv": "P-384",
    "x": "sbcDneKt_Q4fImuyMtturQbz67Mf3Y79wmKv1A07r3FmbxJaN1tReSG8OMH2B-Ft",
    "y": "X4qf2gemrer8xJnzW4Rer2VmN11f8TkDyLRc8-XsfBMtvRvC8gyWEQ2IImnL8pAC"
  }
}
```

#### Encapsulate and publish the verification method

The exported verification method document can be further encapsulated in a controlled identifier document (e.g., a DID
document) and published to a public storage or bulletin, which could be used for proof verification. A verification
method can either be directly wrapped to generated a new document, or added to an existing document by passing the
document as the second parameter of the `encapsulateVerificationMethod()` function.

```typescript
import { document } from "@herculas/vc-data-integrity"

const didDocument = document.encapsulateVerificationMethod(
  method,
  undefined,
  new Set(["assertionMethod"]),
)
```

The third parameter specified the [verification relationship](https://www.w3.org/TR/cid/#verification-relationships).
The generated document looks like:

```json
{
  "@context": "https://www.w3.org/ns/cid/v1",
  "id": "did:example:1145141919810",
  "verificationMethod": [
    {
      "id": "did:example:1145141919810#-ZfIG4j_rW58OTC8F4WIAMA7s4Ig81mvp1Yoiu6p5mY=",
      "type": "JsonWebKey",
      "controller": "did:example:1145141919810",
      "secretKeyJwk": {
        "kty": "EC",
        "use": "sig",
        "key_ops": ["sign"],
        "alg": "ES384",
        "ext": true,
        "crv": "P-384",
        "x": "sbcDneKt_Q4fImuyMtturQbz67Mf3Y79wmKv1A07r3FmbxJaN1tReSG8OMH2B-Ft",
        "y": "X4qf2gemrer8xJnzW4Rer2VmN11f8TkDyLRc8-XsfBMtvRvC8gyWEQ2IImnL8pAC",
        "d": "N-c2EJK-pH68ZmQYv4FRzHMgZBA0XKGz2F5u777FE3QCSW60FCKAWIIoaAi7JQre"
      },
      "publicKeyJwk": {
        "kty": "EC",
        "use": "sig",
        "key_ops": ["verify"],
        "alg": "ES384",
        "ext": true,
        "crv": "P-384",
        "x": "sbcDneKt_Q4fImuyMtturQbz67Mf3Y79wmKv1A07r3FmbxJaN1tReSG8OMH2B-Ft",
        "y": "X4qf2gemrer8xJnzW4Rer2VmN11f8TkDyLRc8-XsfBMtvRvC8gyWEQ2IImnL8pAC"
      }
    }
  ],
  "assertionMethod": [
    "did:example:1145141919810#-ZfIG4j_rW58OTC8F4WIAMA7s4Ig81mvp1Yoiu6p5mY="
  ]
}
```

#### Import keypair instances

External obtained verification methods can also be imported into a ECDSA keypair instance.

```typescript
const importedKeypair = await ECKeypair.import(method, {
  curve: "P-256",
})
```

The `import()` method accepts verification method document and an `options`, which could specify the following fields:

- `curve`: specifies the elliptic curve of the imported keypair. It defaults to `P-256`.
- `checkContext`: indicates whether to check the `@context` field of the imported document. It defaults to `false`.
- `checkExpired`: indicates whether to check the expiration time of the imported document. It defaults to `false`.
- `checkRevoked`: indicates whether to check the revocation status of the imported document. It defaults to `false`.

### Data integrity proofs

This cryptosuite implementation provides two base cryptographic suites for data integrity proofs: `ecdsa-rdfc-2019` and
`ecdsa-jcs-2019`. The `ecdsa-rdfc-2019` suite uses the
[RDF Dataset Canonicalization Algorithm](https://www.w3.org/TR/rdf-canon/) to transform the input document into its
canonical form, while the `ecdsa-jcs-2019` suite uses the
[JSON Canonicalization Scheme](https://datatracker.ietf.org/doc/html/rfc8785).

Here, we use the `ecdsa-rdfc-2019` suite as an example to demonstrate how to generate and verify data integrity proofs.
The `ecdsa-jcs-2019` suite is similar to the `ecdsa-rdfc-2019` suite, and the usage is the same.

#### Generate proofs

The following is the document to be proven:

```typescript
import { Credential } from "@herculas/vc-data-integrity"

const unsecuredCredential: Credential = {
  "@context": [
    "https://www.w3.org/ns/credentials/v2",
    "https://www.w3.org/ns/credentials/examples/v2",
  ],
  id: "urn:uuid:58172aac-d8ba-11ed-83dd-0b3aef56cc33",
  type: ["VerifiableCredential", "AlumniCredential"],
  name: "Alumni Credential",
  description: "A minimum viable example of an Alumni Credential.",
  issuer: "https://vc.example/issuers/5678",
  validFrom: "2023-01-01T00:00:00Z",
  credentialSubject: {
    id: "did:example:abcdefgh",
    alumniOf: "The School of Examples",
  },
}
```

To generate a data integrity proof, you need first to construct a proof options object, which specifies the metadata for
the proof, including the verification method, the suite, and the purpose of the proof.

```typescript
import { Proof } from "@herculas/vc-data-integrity"

const proofOptions: Proof = {
  "@context": [
    "https://www.w3.org/ns/credentials/v2",
    "https://www.w3.org/ns/credentials/examples/v2",
  ],
  type: "DataIntegrityProof",
  cryptosuite: "ecdsa-rdfc-2019",
  created: "2023-02-24T23:36:38Z",
  verificationMethod:
    "did:key:zDnaepBuvsQ8cpsWrVKw8fbpGpvPeNSjVPTWoq6cRqaYzBKVP#zDnaepBuvsQ8cpsWrVKw8fbpGpvPeNSjVPTWoq6cRqaYzBKVP",
  proofPurpose: "assertionMethod",
}
```

Then, you can generate the proof by calling the `createProof()` method, providing the `unsecuredCredential` and the
`proofOptions` as parameters.

```typescript
import { EcdsaRdfc2019 } from "@herculas/vc-suite-ecdsa"

const proof = await EcdsaRdfc2019.createProof(
  unsecuredCredential,
  {
    curve: "P-256",
    proof: proofOptions,
    documentLoader: loader,
  },
)
```

The `createProof()` method accepts an `options` object as parameter, which MUST specify the following fields:

- `curve`: the elliptic curve of the keypair used to generate the proof.
- `proof`: the proof options object.
- `documentLoader`: the document loader function used to resolve external documents, including any JSON-LD contexts and
  verification methods referenced in the input document.

The generated proof looks like:

```json
{
  "@context": [
    "https://www.w3.org/ns/credentials/v2",
    "https://www.w3.org/ns/credentials/examples/v2"
  ],
  "type": "DataIntegrityProof",
  "cryptosuite": "ecdsa-rdfc-2019",
  "created": "2023-02-24T23:36:38Z",
  "verificationMethod": "did:key:zDnaepBuvsQ8cpsWrVKw8fbpGpvPeNSjVPTWoq6cRqaYzBKVP#zDnaepBuvsQ8cpsWrVKw8fbpGpvPeNSjVPTWoq6cRqaYzBKVP",
  "proofPurpose": "assertionMethod",
  "proofValue": "z5yYFsx6DvPPXme4UHrrKyYqueJxqh1f7twKtDUC5EWod92jgg3a3mRhnYa2cS1ggwSUhgr8V2T8BgBVjwyVPWbrw"
}
```

#### Verify proofs

The following is a document secured by a data integrity proof:

```json
{
  "@context": [
    "https://www.w3.org/ns/credentials/v2",
    "https://www.w3.org/ns/credentials/examples/v2"
  ],
  "id": "urn:uuid:58172aac-d8ba-11ed-83dd-0b3aef56cc33",
  "type": [
    "VerifiableCredential",
    "AlumniCredential"
  ],
  "name": "Alumni Credential",
  "description": "A minimum viable example of an Alumni Credential.",
  "issuer": "https://vc.example/issuers/5678",
  "validFrom": "2023-01-01T00:00:00Z",
  "credentialSubject": {
    "id": "did:example:abcdefgh",
    "alumniOf": "The School of Examples"
  },
  "proof": {
    "@context": [
      "https://www.w3.org/ns/credentials/v2",
      "https://www.w3.org/ns/credentials/examples/v2"
    ],
    "type": "DataIntegrityProof",
    "cryptosuite": "ecdsa-rdfc-2019",
    "created": "2023-02-24T23:36:38Z",
    "verificationMethod": "did:key:zDnaepBuvsQ8cpsWrVKw8fbpGpvPeNSjVPTWoq6cRqaYzBKVP#zDnaepBuvsQ8cpsWrVKw8fbpGpvPeNSjVPTWoq6cRqaYzBKVP",
    "proofPurpose": "assertionMethod",
    "proofValue": "z5yYFsx6DvPPXme4UHrrKyYqueJxqh1f7twKtDUC5EWod92jgg3a3mRhnYa2cS1ggwSUhgr8V2T8BgBVjwyVPWbrw"
  }
}
```

To verify the data integrity proof, you need to call the `verifyProof()` method, providing the secured document as the
parameter.

```typescript
const result = await EcdsaRdfc2019.verifyProof(
  securedCredential,
  {
    curve: "P-256",
    documentLoader: loader,
  },
)
```

The result of the verification is a boolean value `verified` indicating whether the proof is valid, along with the
verified document:

```json
{
  "verified": true,
  "verifiedDocument": {
    "@context": [
      "https://www.w3.org/ns/credentials/v2",
      "https://www.w3.org/ns/credentials/examples/v2"
    ],
    "id": "urn:uuid:58172aac-d8ba-11ed-83dd-0b3aef56cc33",
    "type": [
      "VerifiableCredential",
      "AlumniCredential"
    ],
    "name": "Alumni Credential",
    "description": "A minimum viable example of an Alumni Credential.",
    "issuer": "https://vc.example/issuers/5678",
    "validFrom": "2023-01-01T00:00:00Z",
    "credentialSubject": {
      "id": "did:example:abcdefgh",
      "alumniOf": "The School of Examples"
    }
  }
}
```

### Selective disclosure

This cryptosuite implementation provides a selective disclosure cryptographic suite `ecdsa-sd-2023` for generating and
verifying selective disclosure proofs. The selective disclosure proof is a data integrity proof that derives from a base
proof issued by the issuer, containing a list of revealed attributes and a list of hidden attributes.

#### Generate base proofs

In a scenario, a holder will be issued an employment authorization document as shown below:

```json
{
  "@context": [
    "https://www.w3.org/ns/credentials/v2",
    "https://w3id.org/citizenship/v4rc1"
  ],
  "type": [
    "VerifiableCredential",
    "EmploymentAuthorizationDocumentCredential"
  ],
  "issuer": {
    "id": "did:key:zDnaegE6RR3atJtHKwTRTWHsJ3kNHqFwv7n9YjTgmU7TyfU76",
    "image": "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVQIW2NgUPr/HwADaAIhG61j/AAAAABJRU5ErkJggg=="
  },
  "credentialSubject": {
    "type": [
      "Person",
      "EmployablePerson"
    ],
    "givenName": "JOHN",
    "additionalName": "JACOB",
    "familyName": "SMITH",
    "image": "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVQIW2Ng+M/wHwAEAQH/7yMK/gAAAABJRU5ErkJggg==",
    "gender": "Male",
    "residentSince": "2015-01-01",
    "birthCountry": "Bahamas",
    "birthDate": "1999-07-17",
    "employmentAuthorizationDocument": {
      "type": "EmploymentAuthorizationDocument",
      "identifier": "83627465",
      "lprCategory": "C09",
      "lprNumber": "999-999-999"
    }
  },
  "name": "Employment Authorization Document",
  "description": "Example Employment Authorization Document.",
  "validFrom": "2019-12-03T00:00:00Z",
  "validUntil": "2029-12-03T00:00:00Z"
}
```

To generate a base proof, the issuer need first to construct a proof options object, which specifies the metadata for
the proof, including the verification method, the suite, and the purpose of the proof.

```typescript
import { Proof } from "@herculas/vc-data-integrity"

const proofOptions: Proof = {
  "@context": [
    "https://www.w3.org/ns/credentials/v2",
    "https://w3id.org/citizenship/v4rc1"
  ]
  type: "DataIntegrityProof",
  cryptosuite: "ecdsa-sd-2023",
  created: "2023-08-15T23:36:38Z",
  verificationMethod: "did:key:zDnaepBuvsQ8cpsWrVKw8fbpGpvPeNSjVPTWoq6cRqaYzBKVP#zDnaepBuvsQ8cpsWrVKw8fbpGpvPeNSjVPTWoq6cRqaYzBKVP",
  proofPurpose: "assertionMethod",
}
```

Then, the issuer generates the base proof by calling the `createProof()` method, providing the `unsecuredCredential` and
the `proofOptions` as parameters.

```typescript
import { EcdsaSd2023 } from "@herculas/vc-suite-ecdsa"

const proof = await EcdsaSd2023.createProof(unsecuredCredential, {
  curve: "P-256",
  proof: proofOptions,
  mandatoryPointers: ["/issuer"],
  documentLoader: loader,
})
```

Note that, compared to the data integrity proof, the proof here requires an additional parameter `mandatoryPointers`,
which is an array of JSON Pointers pointing to the attributes that must be revealed. Here we specify that the `issuer`
attribute must be revealed.

The generated proof looks like:

```json
{
  "@context": [
    "https://www.w3.org/ns/credentials/v2",
    "https://w3id.org/citizenship/v4rc1"
  ],
  "type": "DataIntegrityProof",
  "cryptosuite": "ecdsa-sd-2023",
  "created": "2023-08-15T23:36:38Z",
  "verificationMethod": "did:key:zDnaepBuvsQ8cpsWrVKw8fbpGpvPeNSjVPTWoq6cRqaYzBKVP#zDnaepBuvsQ8cpsWrVKw8fbpGpvPeNSjVPTWoq6cRqaYzBKVP",
  "proofPurpose": "assertionMethod",
  "proofValue": "u2V0AhVhAM_S_TACn9YQJdyyQLbOqp9RPvu236WZy6D5RSef7GiDhsHgBm0gCMDGdavS27q7o0MfH8f4LNnRCivGgClF9zFgjgCQD3nyVRxzwrPt0lgfxg4h6iFr6tAufwEbjp3C_y2V1x5dYIGnVoHkBsWXCIFbtYFgCD1Lls-bhuDa3_cdizw61bvJjlFhApH-7KxLKStZBVf71vWHXc8ydmUjjI_GU4VcJPH_xFPXLr4OlSlWVt4lfApyR4Nne1tU6gpXseiUkovgQbg9RwVhAEMfZKHlSU3E9i5OII_R8NsXBhrn8HakCNn36j0P4FTvarFyv3en-0HZbLYaQQgHh-927kCeuHlakaLhusySyz1hAOy7k95qh71vmxI0CezHU_4L8Lyi_WiiOczb59hb_E2gngmudyVnTN0xlN2omd-EKAYM75Ofe2C4EUE5mYZc99VhAl7Cgl8KiYRzX5ibnkrHS-ye7ez2AEKrbp5R1gr-jP2qaUsyweYK8S_OduiO3etOFE7DUhoKuPAsS4TbdYsZLrVhAgcvfS_en15keONk286l8sn8AsAl3qC92QdfGBeSMUCh2BYxwV192t15jDTqOTAK-1V0-sJTRYSs357k_givzz1hAFiQbs3R1WLyslbJnrc4COCUtlN8bDxbEegLfn3S9DhM4wKSEKDGK5zXI3MHC9YGsqFjrUL26QKKiFz3tCJDNi1hAJ4mo4Ld9S-WBcBPn_hGgoC1xc4TsZ-rTTXd65NUKmRffzAR1GHlc8CKzjder1Ddl4Cvipyb8ehfWmk31Tv48blhAjbQDJad_SSsy2isJz5JJYcxRhMBWWJn90tAnGOHRy6NEehezYviMjintmzD7BzOqr_tP-UcZqpraB7LDqwwzo1hAm5iKsMna4ht7nEnYMTrVJ4FYCDmrzFnFtK37KCSNDYlFrxS9Qv1mU-AlSM1vVxwjKThwWBYayeczkNHhHN2CQFhAUTRwmVIvFTSOgaM9wk7xDpbgPyfOLxP8__rl9SsIkImeOPR_NwbyLVc1_S-ARtYvpRRyU0txuuJ4dKGrNreiF1hArTr1F0_dFCUNPz4z7tLxU6qOg_HBB-Br7ZCRZmVIq5D5MwLawNw5Ey05yQIuH_UTuNcsjqKDtfIIIhWe68CHtVhAE-k3vrNbBmho_tSq7qPiMbTw4XTpv990n-rUTLUcrE1VWrd1CdAt7yx7nfESM0kMIUrSIxCXUKoi-v4k7me-w1hA9k_LUOGOfYeRT-KbHRhnAXbbfMjfhjoh8qFe7PHlH3gXFMb9I9YGMjmd220jhFGSY1lKvYpw_8xO72EE3xu3gVhAUgMvaP4o7geLw6X4zoGjB92hZc3__rgv6G00lSnTMz7M7Nga60pNlDVkXz-1Xjn-vZOhM7bFaUSvi9fqvrDhI1hAklcGbwlm58VDxYxjsre-RwYquHC6YSOisaByBQO4CmEvXa-sN1usWugfjx8YnaxXbR4Fe2_mN34AtFwYS5ECIlhAt0Fu_R9atFBDlmjZQ7ppsw7dvA1YaKsrfqwL1wbIo8FAYkZTG8I4pigpjsbP_5L1NQmQtea3G3nmqyxuBNKaoFhAgcXxMfQtpsBsSqGx3-E61gKFaYPZZv7yz9nXDsc1iDOdO3xD5ZYlvhLA4fVMLmaYHiZNhW94FElz0MNb1kca5lhAdh0yyXJJmAJjYtDmQWoYnTcMt5My9zp9mZDCtU1O56P52YE1xbeciMha4pU3F3gSEoLsR4EdWJK_-TZWAJsHr1hA6nN6S3X2-_waP7ogjE0VZuNgqGIdzq3EIQX4suOd7BgNDOELBYmfwnyo_XI6Gqgqyn6P5E5TZr4t7gAJLm8C71hAAR1GJ4PqQG8rO66kqRAmuldlyuSVqcj-Ks9lhqvaLAi_54j8Ww4Nmg5k7YxKyDzGk-zC9vZFtV6pgn0ousO69YFnL2lzc3Vlcg"
}
```

#### Derive selective proofs

To derive a proof with selective disclosure, the holder starts with a secured document containing a base proof issued by
the issuer.

```typescript
const derivedProof = await EcdsaSd2023.deriveProof(securedCredential, {
  curve: "P-256",
  documentLoader: loader,
  selectivePointers: ["/validFrom", "/validUntil", "/credentialSubject/birthCountry"],
})
```

Note that the `options` parameter of the `deriveProof()` method requires an additional field `selectivePointers`, which
is an array of JSON Pointers pointing to the attributes that is to be disclosed to the verifier. Here we specify that
the `validFrom`, `validUntil`, and `birthCountry` attributes will be revealed.

The derived proof looks like:

```json
{
  "@context": [
    "https://www.w3.org/ns/credentials/v2",
    "https://w3id.org/citizenship/v4rc1"
  ],
  "type": "DataIntegrityProof",
  "cryptosuite": "ecdsa-sd-2023",
  "created": "2023-08-15T23:36:38Z",
  "verificationMethod": "did:key:zDnaepBuvsQ8cpsWrVKw8fbpGpvPeNSjVPTWoq6cRqaYzBKVP#zDnaepBuvsQ8cpsWrVKw8fbpGpvPeNSjVPTWoq6cRqaYzBKVP",
  "proofPurpose": "assertionMethod",
  "proofValue": "u2V0BhVhAM_S_TACn9YQJdyyQLbOqp9RPvu236WZy6D5RSef7GiDhsHgBm0gCMDGdavS27q7o0MfH8f4LNnRCivGgClF9zFgjgCQD3nyVRxzwrPt0lgfxg4h6iFr6tAufwEbjp3C_y2V1x5eGWEA7LuT3mqHvW-bEjQJ7MdT_gvwvKL9aKI5zNvn2Fv8TaCeCa53JWdM3TGU3aiZ34QoBgzvk597YLgRQTmZhlz31WECXsKCXwqJhHNfmJueSsdL7J7t7PYAQqtunlHWCv6M_appSzLB5grxL8526I7d604UTsNSGgq48CxLhNt1ixkutWECBy99L96fXmR442TbzqXyyfwCwCXeoL3ZB18YF5IxQKHYFjHBXX3a3XmMNOo5MAr7VXT6wlNFhKzfnuT-CK_PPWEBRNHCZUi8VNI6Boz3CTvEOluA_J84vE_z_-uX1KwiQiZ449H83BvItVzX9L4BG1i-lFHJTS3G64nh0oas2t6IXWECtOvUXT90UJQ0_PjPu0vFTqo6D8cEH4GvtkJFmZUirkPkzAtrA3DkTLTnJAi4f9RO41yyOooO18ggiFZ7rwIe1WEB2HTLJckmYAmNi0OZBahidNwy3kzL3On2ZkMK1TU7no_nZgTXFt5yIyFrilTcXeBISguxHgR1Ykr_5NlYAmwevogBYIJ6R_VNl8PfumaaACrBuSM47IB3BP3iTxwjBDo6Sy_7SAVggMrcLF2Sz3tZhlj13INm_eoSQhgBmkkFGvzl-g2gNPD-EAAECBA"
}
```

#### Generate revealed documents

The holder can then generate a revealed document by appending the selective pointers to the mandatory pointers, and
selecting the attributes to be revealed.

```typescript
import { selective } from "@herculas/vc-data-integrity"

const revealedPointers = ["/issuer", "/validFrom", "/validUntil", "/credentialSubject/birthCountry"]
const revealedCredential = selective.selectJsonLd(revealedPointers, securedCredential) as Credential
revealedCredential.proof = derived
```

The revealed credential looks like:

```json
{
  "@context": [
    "https://www.w3.org/ns/credentials/v2",
    "https://w3id.org/citizenship/v4rc1"
  ],
  "type": [
    "VerifiableCredential",
    "EmploymentAuthorizationDocumentCredential"
  ],
  "issuer": {
    "id": "did:key:zDnaegE6RR3atJtHKwTRTWHsJ3kNHqFwv7n9YjTgmU7TyfU76",
    "image": "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVQIW2NgUPr/HwADaAIhG61j/AAAAABJRU5ErkJggg=="
  },
  "validFrom": "2019-12-03T00:00:00Z",
  "validUntil": "2029-12-03T00:00:00Z",
  "credentialSubject": {
    "type": [
      "Person",
      "EmployablePerson"
    ],
    "birthCountry": "Bahamas"
  },
  "proof": {
    "@context": [
      "https://www.w3.org/ns/credentials/v2",
      "https://w3id.org/citizenship/v4rc1"
    ],
    "type": "DataIntegrityProof",
    "cryptosuite": "ecdsa-sd-2023",
    "created": "2023-08-15T23:36:38Z",
    "verificationMethod": "did:key:zDnaepBuvsQ8cpsWrVKw8fbpGpvPeNSjVPTWoq6cRqaYzBKVP#zDnaepBuvsQ8cpsWrVKw8fbpGpvPeNSjVPTWoq6cRqaYzBKVP",
    "proofPurpose": "assertionMethod",
    "proofValue": "u2V0BhVhAM_S_TACn9YQJdyyQLbOqp9RPvu236WZy6D5RSef7GiDhsHgBm0gCMDGdavS27q7o0MfH8f4LNnRCivGgClF9zFgjgCQD3nyVRxzwrPt0lgfxg4h6iFr6tAufwEbjp3C_y2V1x5eGWEA7LuT3mqHvW-bEjQJ7MdT_gvwvKL9aKI5zNvn2Fv8TaCeCa53JWdM3TGU3aiZ34QoBgzvk597YLgRQTmZhlz31WECXsKCXwqJhHNfmJueSsdL7J7t7PYAQqtunlHWCv6M_appSzLB5grxL8526I7d604UTsNSGgq48CxLhNt1ixkutWECBy99L96fXmR442TbzqXyyfwCwCXeoL3ZB18YF5IxQKHYFjHBXX3a3XmMNOo5MAr7VXT6wlNFhKzfnuT-CK_PPWEBRNHCZUi8VNI6Boz3CTvEOluA_J84vE_z_-uX1KwiQiZ449H83BvItVzX9L4BG1i-lFHJTS3G64nh0oas2t6IXWECtOvUXT90UJQ0_PjPu0vFTqo6D8cEH4GvtkJFmZUirkPkzAtrA3DkTLTnJAi4f9RO41yyOooO18ggiFZ7rwIe1WEB2HTLJckmYAmNi0OZBahidNwy3kzL3On2ZkMK1TU7no_nZgTXFt5yIyFrilTcXeBISguxHgR1Ykr_5NlYAmwevogBYIJ6R_VNl8PfumaaACrBuSM47IB3BP3iTxwjBDo6Sy_7SAVggMrcLF2Sz3tZhlj13INm_eoSQhgBmkkFGvzl-g2gNPD-EAAECBA"
  }
}
```

#### Verify derived proofs

Finally, the verifier can verify the derived proof by calling the `verifyProof()` method, providing the revealed
document as the parameter.

```typescript
const result = await EcdsaSd2023.verifyProof(revealedCredential, {
  curve: "P-256",
  documentLoader: loader,
})
```

The result of the verification is a boolean value `verified` indicating whether the proof is valid, along with the
verified document:

```json
{
  "verified": true,
  "verifiedDocument": {
    "@context": [
      "https://www.w3.org/ns/credentials/v2",
      "https://w3id.org/citizenship/v4rc1"
    ],
    "type": [
      "VerifiableCredential",
      "EmploymentAuthorizationDocumentCredential"
    ],
    "issuer": {
      "id": "did:key:zDnaegE6RR3atJtHKwTRTWHsJ3kNHqFwv7n9YjTgmU7TyfU76",
      "image": "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVQIW2NgUPr/HwADaAIhG61j/AAAAABJRU5ErkJggg=="
    },
    "validFrom": "2019-12-03T00:00:00Z",
    "validUntil": "2029-12-03T00:00:00Z",
    "credentialSubject": {
      "type": [
        "Person",
        "EmployablePerson"
      ],
      "birthCountry": "Bahamas"
    }
  }
}
```
