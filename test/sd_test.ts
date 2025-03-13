import { assert } from "@std/assert"
import { type Credential, type Proof, selective } from "@herculas/vc-data-integrity"

import { Curve } from "../src/constant/curve.ts"
import { EcdsaSd2023 } from "../src/suite/sd.ts"
import { testLoader } from "./mock/loader.ts"

import * as UNSECURED_CRED_2 from "./mock/unsecured-credential-2.json" with { type: "json" }
import * as UNSECURED_CRED_3 from "./mock/unsecured-credential-3.json" with { type: "json" }
import * as PROOF_OPTIONS_5 from "./mock/proof-options-5.json" with { type: "json" }
import * as PROOF_OPTIONS_6 from "./mock/proof-options-6.json" with { type: "json" }

Deno.test("ECDSA-SD-2023: case 1 (P-256)", async () => {
  const unsecuredCredential = structuredClone(UNSECURED_CRED_2.default) as Credential
  const proofOptions = structuredClone(PROOF_OPTIONS_5.default) as Proof

  const mandatoryPointers = ["/issuer"]
  const curve = Curve.P256

  const createOptions = {
    curve,
    proof: proofOptions,
    mandatoryPointers,
    documentLoader: testLoader,
  }

  const proof = await EcdsaSd2023.createProof(unsecuredCredential, createOptions)

  const securedCredential = structuredClone(unsecuredCredential)
  securedCredential.proof = proof

  const selectivePointers = ["/validFrom", "/validUntil", "/credentialSubject/birthCountry"]
  const deriveOptions = {
    curve,
    documentLoader: testLoader,
    selectivePointers,
  }

  const derived = await EcdsaSd2023.deriveProof(securedCredential, deriveOptions)

  const revealedPointers = mandatoryPointers.concat(selectivePointers)
  const revealedCredential = selective.selectJsonLd(revealedPointers, securedCredential) as Credential
  revealedCredential.proof = derived

  const verifyOptions = {
    curve,
    documentLoader: testLoader,
  }

  const result = await EcdsaSd2023.verifyProof(revealedCredential, verifyOptions)
  assert(result.verified)
})

Deno.test("ECDSA-SD-2023: case 2 (P-256)", async () => {
  const unsecuredCredential = structuredClone(UNSECURED_CRED_3.default) as Credential
  const proofOptions = structuredClone(PROOF_OPTIONS_5.default) as Proof

  const mandatoryPointers = ["/issuer"]
  const curve = Curve.P256

  const createOptions = {
    curve,
    proof: proofOptions,
    mandatoryPointers,
    documentLoader: testLoader,
  }

  const proof = await EcdsaSd2023.createProof(unsecuredCredential, createOptions)

  const securedCredential = structuredClone(unsecuredCredential)
  securedCredential.proof = proof

  const selectivePointers = ["/validFrom", "/validUntil", "/credentialSubject/birthCountry"]
  const deriveOptions = {
    curve,
    documentLoader: testLoader,
    selectivePointers,
  }

  const derived = await EcdsaSd2023.deriveProof(securedCredential, deriveOptions)

  const revealedPointers = mandatoryPointers.concat(selectivePointers)
  const revealedCredential = selective.selectJsonLd(revealedPointers, securedCredential) as Credential
  revealedCredential.proof = derived

  const verifyOptions = {
    curve,
    documentLoader: testLoader,
  }

  const result = await EcdsaSd2023.verifyProof(revealedCredential, verifyOptions)
  assert(result.verified)
})

Deno.test("ECDSA-SD-2023: case 3 (P-384)", async () => {
  const unsecuredCredential = structuredClone(UNSECURED_CRED_2.default) as Credential
  const proofOptions = structuredClone(PROOF_OPTIONS_6.default) as Proof

  const mandatoryPointers = ["/issuer"]
  const curve = Curve.P384

  const createOptions = {
    curve,
    proof: proofOptions,
    mandatoryPointers,
    documentLoader: testLoader,
  }

  const proof = await EcdsaSd2023.createProof(unsecuredCredential, createOptions)

  // const securedCredential = structuredClone(unsecuredCredential)
  // securedCredential.proof = proof

  // const selectivePointers = ["/validFrom", "/validUntil", "/credentialSubject/birthCountry"]
  // const deriveOptions = {
  //   curve,
  //   documentLoader: testLoader,
  //   selectivePointers,
  // }

  // const derived = await EcdsaSd2023.deriveProof(securedCredential, deriveOptions)

  // const revealedPointers = mandatoryPointers.concat(selectivePointers)
  // const revealedCredential = selective.selectJsonLd(revealedPointers, securedCredential) as Credential
  // revealedCredential.proof = derived

  // const verifyOptions = {
  //   curve,
  //   documentLoader: testLoader,
  // }

  // const result = await EcdsaSd2023.verifyProof(revealedCredential, verifyOptions)
  // assert(result.verified)
})
