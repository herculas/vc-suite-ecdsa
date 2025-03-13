import {
  type Canonize,
  type Compact,
  type Expand,
  format,
  type Hasher,
  type HMAC,
  type JsonLdObject,
  type LabelMap,
  type NQuad,
  type Proof,
  rdfc,
  selective,
  type ToRdf,
  type URNScheme,
} from "@herculas/vc-data-integrity"

import { Curve } from "../constant/curve.ts"
import { parseBaseProofValue, parseDerivedProofValue } from "./serialize.ts"
import type { DisclosureData, VerifyData } from "./types.ts"
import { curveToDigestAlgorithm } from "../utils/crypto.ts"

/**
 * Serialize the data that is to be signed by the private key associated with the base proof verification method.
 *
 * @param {Uint8Array} proofHash The proof options hash.
 * @param {Uint8Array} publicKey The proof-scoped multikey-encoded public key.
 * @param {Uint8Array} mandatoryHash The mandatory hash.
 *
 * @returns {Uint8Array} A serialized sign data, which is the concatenation of the proof hash, public key, and mandatory
 * hash, in that order.
 *
 * @see https://www.w3.org/TR/vc-di-ecdsa/#serializesigndata
 */
export function serializeSignData(
  proofHash: Uint8Array,
  publicKey: Uint8Array,
  mandatoryHash: Uint8Array,
): Uint8Array {
  // Procedure:
  //
  // 1. Return the concatenation of `proofHash`, `publicKey`, and `mandatoryHash`, in that order, as sign data.

  return format.concatenate(proofHash, publicKey, mandatoryHash)
}

/**
 * Create data to be used to generate a derived proof.
 *
 * @param {JsonLdDocument} document A JSON-LD document.
 * @param {Proof} proof An ECDSA-SD base proof.
 * @param {Array<string>} selectivePointers An array of JSON pointers to used to selectively disclose statements.
 * @param {object} [options] Any custom JSON-LD API options, such as a document loader.
 *
 * @returns {Promise<DisclosureData>} A single object containing the following fields: `baseSignature`, `publicKey`,
 * `signatures`, `labelMap`, `mandatoryIndexes` and `revealDocument`.
 *
 * @see https://www.w3.org/TR/vc-di-ecdsa/#createdisclosuredata
 */
export async function createDisclosureData(
  document: JsonLdObject,
  proof: Proof,
  selectivePointers: Array<string>,
  options?:
    & {
      curve?: Curve
      urnScheme?: URNScheme
      randomString?: string
    }
    & Expand
    & Compact
    & ToRdf
    & Partial<Canonize>,
): Promise<DisclosureData> {
  // Procedure:
  //
  // 1. Initialize `baseSignature`, `publicKey`, `hmacKey`, `signatures`, and `mandatoryPointers` to the values of the
  //    associated properties in the object returned of calling the `parseBaseProofValue` function, passing the
  //    `proofValue` from `proof`.
  // 2. Initialize `hmac` to an HMAC API using `hmacKey`. The HMAC uses the same hash algorithm used in the signature
  //    algorithm, i.e., SHA-256 for a P-256 curve.
  // 3. Initialize `labelMapFactoryFunction` to the result of calling the `createHmacIdLabelMapFunction` function,
  //    passing `hmac`.
  // 4. Initialize `combinedPointers` to the concatenation of `mandatoryPointers` and `selectivePointers`.
  // 5. Initialize `groupDefinitions` to a map with the following entries: key of the string `mandatory` and value of
  //    `mandatoryPointers`, key of the string `selective` and value of `selectivePointers`, and key of the string
  //    `combined` and value of `combinedPointers`.
  // 6. Initialize `groups` and `labelMap` to their associated values in the result of calling the
  //    `canonicalizeAndGroup` function, passing `document`, `labelMapFactoryFunction`, `groupDefinitions`, and any
  //    custom JSON-LD API options as parameters. Note: This step transforms the document into an array of canonical
  //    N-Quad strings with pseudorandom blank node identifiers based on `hmac`, and groups the N-Quad strings according
  //    to selections based on JSON pointers.
  // 7. Initialize `relativeIndex` to zero.
  // 8. Initialize `mandatoryIndexes` to an empty array.
  // 9. For each `absoluteIndex` in the keys in `groups.combined.matching`, convert the absolute index of any mandatory
  //    N-Quad to an index relative to the combined output that is to be revealed:
  //
  //    9.1. If `groups.mandatory.matching` has `absoluteIndex` as a key, then append `relativeIndex` to
  //         `mandatoryIndexes`.
  //    9.2. Increment `relativeIndex`.
  //
  // 10. Determine which signatures match a selectively disclosed statement, which requires incrementing an index
  //     counter while iterating over all `signatures`, skipping over any indexes that match the mandatory group.
  //
  //     10.1. Initialize `index` to 0.
  //     10.2. Initialize `filteredSignatures` to an empty array.
  //     10.3. For each `signature` in `signatures`:
  //
  //           10.3.1. While `index` is in `groups.mandatory.matching`, increment `index`.
  //           10.3.2. If `index` is in `groups.selective.matching`, add `signature` to `filteredSignatures`.
  //           10.3.3. Increment `index`.
  //
  // 11. Initialize `revealDocument` to the result of the calling the `selectJsonLd` function, passing `document`, and
  //     `combinedPointers` as `pointers`.
  // 12. Run the RDF Dataset Canonicalization Algorithm on the joined `combinedGroup.deskolemizedNQuads`, passing any
  //     custom options, and get the canonical bnode identifier map, `canonicalIdMap`. Note: This map includes the
  //     canonical blank node identifiers that a verifier will produce when they canonicalize the reveal document.
  // 13. Initialize `verifierLabelMap` to an empty map. This map will map the canonical blank node identifiers the
  //     verifier will produce when they canonicalize the revealed document to the blank node identifiers that were
  //     originally signed in the base proof.
  // 14. For each key `inputLabel` and value `verifierLabel` in `canonicalIdMap`:
  //
  //     14.1. Add an entry to `verifierLabelMap` using `verifierLabel` as the key and the value associated with
  //           `inputLabel` as a key in `labelMap` as the value.
  //
  // 15. Return an object with properties matching `baseSignature`, `publicKey`, `signatures` for `filteredSignatures`,
  //     `verifierLabelMap` for `labelMap`, `mandatoryIndexes`, and `revealDocument`.

  const curve = options?.curve ?? Curve.P256
  const { baseSignature, publicKey, hmacKey, signatures, mandatoryPointers } = parseBaseProofValue(proof.proofValue!)
  const algorithm = curveToDigestAlgorithm(curve)
  const hmacCryptoKey = await crypto.subtle.importKey(
    "raw",
    hmacKey,
    { name: "HMAC", hash: algorithm },
    true,
    ["sign", "verify"],
  )
  const hmac: HMAC = async (data: Uint8Array) =>
    new Uint8Array(await crypto.subtle.sign(hmacCryptoKey.algorithm, hmacCryptoKey, data))
  const labelMapFactoryFunction = selective.createHmacIdLabelMapFunction(hmac)

  const combinedPointers = [...mandatoryPointers, ...selectivePointers]
  const groupDefinitions: Map<string, Array<string>> = new Map([
    ["mandatory", mandatoryPointers],
    ["selective", selectivePointers],
    ["combined", combinedPointers],
  ])
  const { groups, labelMap } = await selective.canonicalizeAndGroup(
    document,
    labelMapFactoryFunction,
    groupDefinitions,
    options,
  )

  const mandatoryGroup = groups.get("mandatory")!
  const selectiveGroup = groups.get("selective")!
  const combinedGroup = groups.get("combined")!

  let relativeIndex = 0
  const mandatoryIndexes: Array<number> = []
  for (const absoluteIndex of combinedGroup.matching.keys()) {
    if (mandatoryGroup.matching.has(absoluteIndex)) {
      mandatoryIndexes.push(relativeIndex)
    }
    relativeIndex++
  }

  let index = 0
  const filteredSignatures: Array<Uint8Array> = signatures.filter(() => {
    while (mandatoryGroup.matching.has(index)) {
      index++
    }
    return selectiveGroup.matching.has(index++)
  })

  const revealDocument = selective.selectJsonLd(combinedPointers, document)
  let canonicalIdMap: LabelMap = new Map()
  await rdfc.canonize(combinedGroup.deskolemizedNQuads.join(""), {
    ...options,
    algorithm: "RDFC-1.0",
    inputFormat: "application/n-quads",
    format: "application/n-quads",
    canonicalIdMap,
  })
  canonicalIdMap = new Map(
    Array.from(canonicalIdMap, ([key, value]) => [key.replace(/^_:/, ""), value.replace(/^_:/, "")]),
  )

  const verifierLabelMap: LabelMap = new Map()
  for (const [inputLabel, verifierLabel] of canonicalIdMap) {
    verifierLabelMap.set(verifierLabel, labelMap.get(inputLabel)!)
  }

  return {
    baseSignature,
    publicKey,
    signatures: filteredSignatures,
    labelMap: verifierLabelMap,
    mandatoryIndexes,
    revealDocument,
  }
}

/**
 * Create the data needed to perform verification of an ECDSA-SD-protected verifiable credential.
 *
 * @param {JsonLdObject} document A JSON-LD document.
 * @param {Proof} proof An ECDSA-SD disclosure proof.
 * @param {object} [options] Any custom JSON-LD API options, such as a document loader.
 *
 * @returns {Promise<VerifyData>} A single verify data object containing the following fields: `baseSignature`,
 * `proofHash`, `publicKey`, `signatures`, `nonMandatory`, and `mandatoryHash`.
 *
 * @see https://www.w3.org/TR/vc-di-ecdsa/#createverifydata
 */
export async function createVerifyData(
  document: JsonLdObject,
  proof: Proof,
  options?: { curve?: Curve } & ToRdf & Partial<Canonize>,
): Promise<VerifyData> {
  // Procedure:
  //
  // 1. Initialize `proofHash` to the result of perform RDF Dataset Canonicalization on the `proof` options. The hash
  //    used is the same as the one used in the signature algorithm, i.e., SHA-256 for a P-256 curve. Note: This step
  //    can be performed in parallel; it only needs to be completed before this algorithm needs to use the `proofHash`
  //    value.
  // 2. Initialize `baseSignature`, `publicKey`, `signatures`, `labelMap`, and `mandatoryIndexes`, to the values
  //    associated with their property names in the object returned when calling the `parseDerivedProofValue` function,
  //    passing `proofValue` from `proof`.
  // 3. Initialize `labelMapFactoryFunction` to the result of calling the `createLabelMapFunction` function.
  // 4. Initialize `nQuads` to the result of calling the `labelReplacementCanonicalizeJsonLd` function, passing
  //    `document`, `labelMapFactoryFunction`, and any custom JSON-LD API options. Note: This step transforms the
  //    document into an array of canonical N-Quads with pseudorandom blank node identifiers based on `labelMap`.
  // 5. Initialize `mandatory` to an empty array.
  // 6. Initialize `nonMandatory` to an empty array.
  // 7. For each entry (`index`, `nq`) in `nQuads`, separate the N-Quads into mandatory and non-mandatory categories:
  //
  //    7.1. If `mandatoryIndexes` includes `index`, add `nq` to `mandatory`.
  //    7.2. Otherwise, add `nq` to `nonMandatory`.
  //
  // 8. Initialize `mandatoryHash` to the result of calling the `hashMandatory` function, passing `mandatory`.
  // 9. Return an object with properties matching `baseSignature`, `proofHash`, `publicKey`, `signatures`,
  //    `nonMandatory`, and `mandatoryHash`.

  const curve = options?.curve ?? Curve.P256
  const algorithm = curveToDigestAlgorithm(curve)
  const hasher: Hasher = async (data: Uint8Array) => new Uint8Array(await crypto.subtle.digest(algorithm, data))
  const proofHashPromise = _hashCanonizedProof(document, proof, hasher, options)

  const { baseSignature, publicKey, signatures, labelMap, mandatoryIndexes } = parseDerivedProofValue(proof.proofValue!)
  const labelMapFactoryFunction = selective.createLabelMapFunction(labelMap)
  const nQuads = await selective.labelReplacementCanonicalizeJsonLd(document, labelMapFactoryFunction, options)

  const mandatory: Array<NQuad> = []
  const nonMandatory: Array<NQuad> = []

  nQuads.canonicalNQuads.forEach((nq, index) => {
    if (mandatoryIndexes.includes(index)) {
      mandatory.push(nq)
    } else {
      nonMandatory.push(nq)
    }
  })

  const mandatoryHash = await selective.hashMandatoryNQuads(mandatory, hasher)
  return {
    baseSignature,
    proofHash: await proofHashPromise,
    publicKey,
    signatures,
    nonMandatory,
    mandatoryHash,
  }
}

async function _hashCanonizedProof(
  document: JsonLdObject,
  proof: Proof,
  hasher: Hasher,
  options?: ToRdf & Partial<Canonize>,
) {
  options = {
    algorithm: "RDFC-1.0",
    safe: true,
    rdfDirection: "i18n-datatype",
    ...options,
    produceGeneralizedRdf: false,
  }
  proof = {
    "@context": document["@context"],
    ...proof,
  }
  delete proof.proofValue
  const rdf = await rdfc.toRdf(proof, options)
  const canonized = await rdfc.canonize(rdf, options as Canonize)
  return await hasher(new TextEncoder().encode(canonized))
}
