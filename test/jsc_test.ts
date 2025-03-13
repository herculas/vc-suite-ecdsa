import { assert } from "@std/assert"
import type { Credential, Proof } from "@herculas/vc-data-integrity"

import { Curve } from "../src/constant/curve.ts"
import { testLoader } from "./mock/loader.ts"

import * as UNSECURED_CRED_1 from "./mock/unsecured-credential-1.json" with { type: "json" }

import { EcdsaJcs2019 } from "../src/suite/jcs.ts"

import * as PROOF_OPTIONS_3 from "./mock/proof-options-3.json" with { type: "json" }
import * as PROOF_OPTIONS_4 from "./mock/proof-options-4.json" with { type: "json" }

Deno.test("ECDSA-JCS-2019 proof creation and verification encapsulated (P-256)", async () => {
  const unsecuredCredential = structuredClone(UNSECURED_CRED_1.default) as Credential
  const proofOptions = structuredClone(PROOF_OPTIONS_3.default) as Proof

  const curve = Curve.P256
  const proveOptions = { curve, proof: proofOptions, documentLoader: testLoader }
  const proof = await EcdsaJcs2019.createProof(unsecuredCredential, proveOptions)

  const securedCredential = unsecuredCredential
  securedCredential.proof = proof

  const verifyOptions = { curve, documentLoader: testLoader }
  const result = await EcdsaJcs2019.verifyProof(securedCredential, verifyOptions)

  assert(result.verified)
})

Deno.test("ECDSA-JCS-2019 proof creation and verification encapsulated (P-384)", async () => {
  const unsecuredCredential = structuredClone(UNSECURED_CRED_1.default) as Credential
  const proofOptions = structuredClone(PROOF_OPTIONS_4.default) as Proof

  const curve = Curve.P384
  const proveOptions = { curve, proof: proofOptions, documentLoader: testLoader }
  const proof = await EcdsaJcs2019.createProof(unsecuredCredential, proveOptions)

  const securedCredential = unsecuredCredential
  securedCredential.proof = proof

  const verifyOptions = { curve, documentLoader: testLoader }
  const result = await EcdsaJcs2019.verifyProof(securedCredential, verifyOptions)

  assert(result.verified)
})
