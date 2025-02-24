import { assert, assertEquals, assertExists } from "@std/assert"
import { base58btc, type Credential, type Proof } from "@herculas/vc-data-integrity"

import { configRdfc, hash, serialize, transformRdfc, verify } from "../src/suite/core.ts"
import { EcdsaRdfc2019 } from "../src/suite/rdfc.ts"
import { testLoader } from "./mock/loader.ts"

import * as UNSECURED_CRED_1 from "./mock/unsecured-credential-1.json" with { type: "json" }
import * as PROOF_OPTIONS_1 from "./mock/proof-options-1.json" with { type: "json" }
import { Curve } from "../src/constant/curve.ts"

const bytesToHex = (arr: Uint8Array) => arr.reduce((acc, i) => acc + i.toString(16).padStart(2, "0"), "")
const hexToBytes = (hex: string) => new Uint8Array(hex.match(/.{1,2}/g)!.map((byte) => parseInt(byte, 16)))

Deno.test("ECDSA-RDFC-2019 document and proof hashing", async () => {
  const unsecuredCredential = structuredClone(UNSECURED_CRED_1.default) as Credential
  const proofOptions = structuredClone(PROOF_OPTIONS_1.default) as Proof

  const transformOptions = { proof: proofOptions, documentLoader: testLoader }
  const canonicalDocument = await transformRdfc(unsecuredCredential, transformOptions)
  const canonicalProofConfig = await configRdfc(unsecuredCredential, transformOptions)

  const curve = Curve.P256
  const hashData = await hash(canonicalDocument, canonicalProofConfig, curve)

  const expectedDocumentHash = "517744132ae165a5349155bef0bb0cf2258fff99dfe1dbd914b938d775a36017"
  const expectedProofHash = "3a8a522f689025727fb9d1f0fa99a618da023e8494ac74f51015d009d35abc2e"

  assertEquals(bytesToHex(hashData), expectedProofHash + expectedDocumentHash)
})

Deno.test("ECDSA-RDFC-2019 proof creation and verification", async () => {
  const proofOptions = structuredClone(PROOF_OPTIONS_1.default) as Proof

  const documentHash = "517744132ae165a5349155bef0bb0cf2258fff99dfe1dbd914b938d775a36017"
  const proofHash = "3a8a522f689025727fb9d1f0fa99a618da023e8494ac74f51015d009d35abc2e"
  const hashData = proofHash + documentHash

  const options = { curve: Curve.P256, proof: proofOptions, documentLoader: testLoader }
  const proofBytes = await serialize(hexToBytes(hashData), options)
  const result = await verify(hexToBytes(hashData), proofBytes, options)

  assert(result)
})
