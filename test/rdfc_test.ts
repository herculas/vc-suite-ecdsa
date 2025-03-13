import { assert, assertEquals } from "@std/assert"
import { type Credential, format, type Proof } from "@herculas/vc-data-integrity"

import { configRdfc, hashRdfcJcs, serializeRdfcJcs, transformRdfc, verifyRdfcJcs } from "../src/suite/core.ts"
import { Curve } from "../src/constant/curve.ts"
import { EcdsaRdfc2019 } from "../src/suite/rdfc.ts"
import { testLoader } from "./mock/loader.ts"

import * as UNSECURED_CRED_1 from "./mock/unsecured-credential-1.json" with { type: "json" }
import * as UNSECURED_CRED_2 from "./mock/unsecured-credential-2.json" with { type: "json" }
import * as PROOF_OPTIONS_1 from "./mock/proof-options-1.json" with { type: "json" }
import * as PROOF_OPTIONS_2 from "./mock/proof-options-2.json" with { type: "json" }

Deno.test("ECDSA-RDFC-2019 document and proof hashing", async () => {
  const unsecuredCredential = structuredClone(UNSECURED_CRED_1.default) as Credential
  const proofOptions = structuredClone(PROOF_OPTIONS_1.default) as Proof

  const transformOptions = { proof: proofOptions, documentLoader: testLoader }
  const canonicalDocument = await transformRdfc(unsecuredCredential, transformOptions)
  const canonicalProofConfig = await configRdfc(unsecuredCredential, transformOptions)

  const curve = Curve.P256
  const hashData = await hashRdfcJcs(canonicalDocument, canonicalProofConfig, { curve })

  const expectedDocumentHash = "517744132ae165a5349155bef0bb0cf2258fff99dfe1dbd914b938d775a36017"
  const expectedProofHash = "3a8a522f689025727fb9d1f0fa99a618da023e8494ac74f51015d009d35abc2e"

  assertEquals(format.bytesToHex(hashData), expectedProofHash + expectedDocumentHash)
})

Deno.test("ECDSA-RDFC-2019 proof creation and verification", async () => {
  const proofOptions = structuredClone(PROOF_OPTIONS_1.default) as Proof

  const documentHash = "517744132ae165a5349155bef0bb0cf2258fff99dfe1dbd914b938d775a36017"
  const proofHash = "3a8a522f689025727fb9d1f0fa99a618da023e8494ac74f51015d009d35abc2e"
  const hashData = proofHash + documentHash

  const curve = Curve.P256
  const options = { curve, proof: proofOptions, documentLoader: testLoader }
  const proofBytes = await serializeRdfcJcs(format.hexToBytes(hashData), options)
  const result = await verifyRdfcJcs(format.hexToBytes(hashData), proofBytes, options)

  assert(result)
})

Deno.test("ECDSA-RDFC-2019 proof creation and verification encapsulated (P-256)", async () => {
  const unsecuredCredential = structuredClone(UNSECURED_CRED_1.default) as Credential
  const proofOptions = structuredClone(PROOF_OPTIONS_1.default) as Proof

  const curve = Curve.P256
  const proveOptions = { curve, proof: proofOptions, documentLoader: testLoader }
  const proof = await EcdsaRdfc2019.createProof(unsecuredCredential, proveOptions)

  const securedCredential = unsecuredCredential
  securedCredential.proof = proof

  const verifyOptions = { curve, documentLoader: testLoader }
  const result = await EcdsaRdfc2019.verifyProof(securedCredential, verifyOptions)

  assert(result.verified)
})

Deno.test("ECDSA-RDFC-2019 proof creation and verification encapsulated 2 (P-256)", async () => {
  const unsecuredCredential = structuredClone(UNSECURED_CRED_2.default) as Credential
  const proofOptions = structuredClone(PROOF_OPTIONS_1.default) as Proof

  const curve = Curve.P256
  const proveOptions = { curve, proof: proofOptions, documentLoader: testLoader }
  const proof = await EcdsaRdfc2019.createProof(unsecuredCredential, proveOptions)

  const securedCredential = unsecuredCredential
  securedCredential.proof = proof

  const verifyOptions = { curve, documentLoader: testLoader }
  const result = await EcdsaRdfc2019.verifyProof(securedCredential, verifyOptions)

  assert(result.verified)
})

Deno.test("ECDSA-RDFC-2019 proof creation and verification encapsulated (P-384)", async () => {
  const unsecuredCredential = structuredClone(UNSECURED_CRED_1.default) as Credential
  const proofOptions = structuredClone(PROOF_OPTIONS_2.default) as Proof

  const curve = Curve.P384
  const proveOptions = { curve, proof: proofOptions, documentLoader: testLoader }
  const proof = await EcdsaRdfc2019.createProof(unsecuredCredential, proveOptions)

  const securedCredential = unsecuredCredential
  securedCredential.proof = proof

  const verifyOptions = { curve, documentLoader: testLoader }
  const result = await EcdsaRdfc2019.verifyProof(securedCredential, verifyOptions)

  assert(result.verified)
})

Deno.test("ECDSA-RDFC-2019 proof creation and verification encapsulated 2 (P-384)", async () => {
  const unsecuredCredential = structuredClone(UNSECURED_CRED_2.default) as Credential
  const proofOptions = structuredClone(PROOF_OPTIONS_2.default) as Proof

  const curve = Curve.P384
  const proveOptions = { curve, proof: proofOptions, documentLoader: testLoader }
  const proof = await EcdsaRdfc2019.createProof(unsecuredCredential, proveOptions)

  const securedCredential = unsecuredCredential
  securedCredential.proof = proof

  const verifyOptions = { curve, documentLoader: testLoader }
  const result = await EcdsaRdfc2019.verifyProof(securedCredential, verifyOptions)

  assert(result.verified)
})
