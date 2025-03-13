import {
  type Canonize,
  type Compact,
  type Credential,
  document,
  type Expand,
  format,
  type HMAC,
  jcs,
  type LoadDocumentCallback,
  multi,
  ProcessingError,
  ProcessingErrorCode,
  type Proof,
  rdfc,
  selective,
  type ToRdf,
  type URNScheme,
} from "@herculas/vc-data-integrity"

import { constructHasher } from "../utils/crypto.ts"
import { createDisclosureData, serializeSignData } from "../selective/prepare.ts"
import { Curve } from "../constant/curve.ts"
import { ECKeypair } from "../key/keypair.ts"
import { keyToMaterial, materialToMultibase, materialToPublicKey, multibaseToMaterial } from "../key/core.ts"
import { serializeBaseProofValue, serializeDerivedProofValue } from "../selective/serialize.ts"

import * as SUITE_CONSTANT from "../constant/suite.ts"

/**
 * Transform an unsecured input document into a transformed document that is ready to be provided as input to the
 * hashing algorithm.
 *
 * @param {Credential} unsecuredDocument An unsecured input document to transform.
 * @param {object} options A set of options to use when transforming the document. The transformation options MUST
 * contain a type identifier `type` for the cryptographic suite and a cryptosuite identifier `cryptosuite`.
 *
 * @returns {Promise<string>} Resolve to a transformed data document.
 *
 * @see https://www.w3.org/TR/vc-di-ecdsa/#transformation-ecdsa-rdfc-2019
 */
export async function transformRdfc(
  unsecuredDocument: Credential,
  options: {
    proof: Proof
    documentLoader: LoadDocumentCallback
  },
): Promise<string> {
  // Procedure:
  //
  // 1. If `options.type` is not set to the string `DataIntegrityProof`, and `options.cryptosuite` is not set to the
  //    string `ecdsa-rdfc-2019`, an error MUST be raised that SHOULD convey an error type of
  //    `PROOF_TRANSFORMATION_ERROR`.
  // 2. Let `canonicalDocument` be the result of converting `unsecuredDocument` to RDF statements, applying the RDF
  //    Dataset Canonicalization Algorithm to the result, and then serializing the result to a serialized canonical
  //    form.
  // 3. Return `canonicalDocument` as the transformed data document.

  if (
    options.proof.type !== SUITE_CONSTANT.GENERAL_PROOF_TYPE ||
    options.proof.cryptosuite !== SUITE_CONSTANT.SUITE_RDFC
  ) {
    throw new ProcessingError(
      ProcessingErrorCode.PROOF_TRANSFORMATION_ERROR,
      "suite/core#transformRdfc",
      "The proof type or cryptosuite is not supported.",
    )
  }

  const canonicalDocument = await rdfc.normalize(unsecuredDocument, {
    algorithm: "URDNA2015",
    format: "application/n-quads",
    documentLoader: options.documentLoader,
  })

  return canonicalDocument
}

/**
 * Generate a proof configuration from a set of proof options that is used as input to the proof hashing algorithm.
 *
 * @param {Credential} unsecuredDocument An unsecured input document to generate a proof configuration from.
 * @param {object} options A set of proof options to generate a proof configuration from. The proof options MUST contain
 * a type identifier `type` for the cryptographic suite and a cryptosuite identifier `cryptosuite`.
 *
 * @returns {Promise<string>} Resolve to a proof configuration.
 *
 * @see https://www.w3.org/TR/vc-di-ecdsa/#proof-configuration-ecdsa-rdfc-2019
 */
export async function configRdfc(
  unsecuredDocument: Credential,
  options: {
    proof: Proof
    documentLoader: LoadDocumentCallback
  },
): Promise<string> {
  // Procedure:
  //
  // 1. Let `proofConfig` be a clone of the `options` object.
  // 2. If `proofConfig.type` is not set to the string `DataIntegrityProof`, and/or `proofConfig.cryptosuite` is not
  //    set to the string `ecdsa-rdfc-2019`, an error MUST be raised that SHOULD convey an error type of
  //    `PROOF_GENERATION_ERROR`.
  // 3. If `proofConfig.created` is present and set to a value that is not valid datetime, an error MUST be raised
  //    and SHOULD convey an error type of `PROOF_GENERATION_ERROR`.
  // 4. Set `proofConfig.@context` to `unsecuredDocument.@context`.
  // 5. Let `canonicalProofConfig` be the result of applying the RDF Dataset Canonicalization Algorithm to the
  //    `proofConfig`.
  // 6. Return `canonicalProofConfig` as the proof configuration.

  const proofConfig = structuredClone(options.proof)

  if (proofConfig.type !== SUITE_CONSTANT.GENERAL_PROOF_TYPE || proofConfig.cryptosuite !== SUITE_CONSTANT.SUITE_RDFC) {
    throw new ProcessingError(
      ProcessingErrorCode.PROOF_GENERATION_ERROR,
      "suite/core#configRdfc",
      "The proof type or cryptosuite is not supported.",
    )
  }

  if (proofConfig.created && !Date.parse(proofConfig.created)) {
    throw new ProcessingError(
      ProcessingErrorCode.PROOF_GENERATION_ERROR,
      "suite/core#configRdfc",
      "The proof creation date is not a valid datetime.",
    )
  }

  proofConfig["@context"] = unsecuredDocument["@context"]

  const canonicalProofConfig = await rdfc.normalize(proofConfig, {
    algorithm: "URDNA2015",
    format: "application/n-quads",
    documentLoader: options.documentLoader,
  })

  return canonicalProofConfig
}

/**
 * Transform an unsecured input document into a transformed document that is ready to be provided as input to the
 * hashing algorithm.
 *
 * @param {Credential} unsecuredDocument An unsecured input document to transform.
 * @param {object} options A set of options to use when transforming the document. The transformation options MUST
 * contain a type identifier `type` for the cryptographic suite and a cryptosuite identifier `cryptosuite`.
 *
 * @returns {string} A transformed data document.
 *
 * @see https://www.w3.org/TR/vc-di-ecdsa/#transformation-ecdsa-jcs-2019
 */
export function transformJcs(unsecuredDocument: Credential, options: { proof: Proof }): string {
  // Procedure:
  //
  // 1. If `options.type` is not set to the string `DataIntegrityProof`, and `options.cryptosuite` is not set to the
  //    string `ecdsa-jcs-2019`, an error MUST be raised that SHOULD convey an error type of
  //    `PROOF_TRANSFORMATION_ERROR`.
  // 2. Let `canonicalDocument` be the result of applying the JSON Canonicalization Scheme (JCS) to a JSON serialization
  //    of the `unsecuredDocument`.
  // 3. Return `canonicalDocument` as the transformed data document.

  if (
    options.proof.type !== SUITE_CONSTANT.GENERAL_PROOF_TYPE ||
    options.proof.cryptosuite !== SUITE_CONSTANT.SUITE_JCS
  ) {
    throw new ProcessingError(
      ProcessingErrorCode.PROOF_TRANSFORMATION_ERROR,
      "suite/core#transformJcs",
      "The proof type or cryptosuite is not supported.",
    )
  }

  const canonicalDocument = jcs.canonize(unsecuredDocument)
  return canonicalDocument
}

/**
 * Generate a proof configuration from a set of proof options that is used as input to the proof hashing algorithm.
 *
 * @param {object} options A set of proof options to generate a proof configuration from. The proof options MUST contain
 * a type identifier `type` for the cryptographic suite and a cryptosuite identifier `cryptosuite`.
 *
 * @returns {string} A proof configuration.
 *
 * @see https://www.w3.org/TR/vc-di-ecdsa/#proof-configuration-ecdsa-jcs-2019
 */
export function configJcs(options: { proof: Proof }): string {
  // Procedure:
  //
  // 1. Let `proofConfig` be a clone of the `options` object.
  // 2. If `proofConfig.type` is not set to the string `DataIntegrityProof`, or `proofConfig.cryptosuite` is not set to
  //    the string `ecdsa-jcs-2019`, an error MUST be raised that SHOULD convey an error type of
  //    `PROOF_GENERATION_ERROR`.
  // 3. If `proofConfig.created` is present and set to a value that is not valid datetime, an error MUST be raised
  //    and SHOULD convey an error type of `PROOF_GENERATION_ERROR`.
  // 4. Let `canonicalProofConfig` be the result of applying the JSON Canonicalization Scheme (JCS) to `proofConfig`.
  // 5. Return `canonicalProofConfig` as the proof configuration.

  const proofConfig = structuredClone(options.proof)

  if (proofConfig.type !== SUITE_CONSTANT.GENERAL_PROOF_TYPE || proofConfig.cryptosuite !== SUITE_CONSTANT.SUITE_JCS) {
    throw new ProcessingError(
      ProcessingErrorCode.PROOF_GENERATION_ERROR,
      "suite/core#configJcs",
      "The proof type or cryptosuite is not supported.",
    )
  }

  if (proofConfig.created && !Date.parse(proofConfig.created)) {
    throw new ProcessingError(
      ProcessingErrorCode.PROOF_GENERATION_ERROR,
      "suite/core#configJcs",
      "The proof creation date is not a valid datetime.",
    )
  }

  const canonicalProofConfig = jcs.canonize(proofConfig)
  return canonicalProofConfig
}

/**
 * Cryptographically hash a transformed data document and proof configuration into cryptographic hash data that is
 * ready to be provided as input to the proof serialization algorithm and proof verification algorithm.
 *
 * One must use the hash algorithm appropriate in security level to the curve used, i.e., for curve P-256 one uses
 * SHA-256 and for curve P-384 one uses SHA-384.
 *
 * @param {string} transformedDocument A transformed data document to be hashed.
 * @param {string} canonicalProofConfig A canonical proof configuration.
 * @param {object} options A set of options to use when hashing the transformed data document and proof configuration.
 * The options MUST contain a curve identifier `curve` indicating the security level to use.
 *
 * @returns {Promise<Uint8Array>} Resolve to a single hash data represented as series of bytes.
 *
 * @see https://www.w3.org/TR/vc-di-ecdsa/#hashing-ecdsa-rdfc-2019
 * @see https://www.w3.org/TR/vc-di-ecdsa/#hashing-ecdsa-jcs-2019
 */
export async function hashRdfcJcs(
  transformedDocument: string,
  canonicalProofConfig: string,
  options: {
    curve: Curve
  },
): Promise<Uint8Array> {
  // Procedure:
  //
  // 1. Let `proofConfigHash` be the result of applying the SHA-256 or SHA-384 cryptographic hash algorithm to the
  //    respective curve P-256 or curve P-384 `canonicalProofConfig`. Respective `proofConfigHash` will be exactly 32
  //    or 48 bytes in size.
  // 2. Let `transformedDocumentHash` be the result of applying the SHA-256 or SHA-384 cryptographic hash algorithm to
  //    the respective curve P-256 or curve P-384 `transformedDocument`. Respective `transformedDocumentHash` will be
  //    exactly 32 or 48 bytes in size.
  // 3. Let `hashData` be the result of concatenating `proofConfigHash` followed by `transformedDocumentHash`.
  // 4. Return `hashData` as the hash data.

  const hasher = constructHasher(options.curve)
  const proofConfigHash = await hasher(new TextEncoder().encode(canonicalProofConfig))
  const transformedDocumentHash = await hasher(new TextEncoder().encode(transformedDocument))
  const hashData = format.concatenate(proofConfigHash, transformedDocumentHash)
  return hashData
}

/**
 * Serialize a digital signature from a set of cryptographic hash data.
 *
 * @param {Uint8Array} hashData A cryptographic hash data to serialize.
 * @param {object} options A set of options to use when serializing the hash data.
 *
 * @returns {Promise<Uint8Array>} Resolve to a serialized digital proof.
 *
 * @see https://www.w3.org/TR/vc-di-ecdsa/#proof-serialization-ecdsa-rdfc-2019
 * @see https://www.w3.org/TR/vc-di-ecdsa/#proof-serialization-ecdsa-jcs-2019
 */
export async function serializeRdfcJcs(
  hashData: Uint8Array,
  options: {
    curve: Curve
    proof: Proof
    documentLoader: LoadDocumentCallback
  },
): Promise<Uint8Array> {
  // Procedure:
  //
  // 1. Let `privateKeyBytes` be the result of retrieving the private key bytes associated with the
  //    `options.verificationMethod` value.
  // 2. Let `proofBytes` be the result of applying the Elliptic Curve Digital Signature Algorithm (ECDSA), with
  //    `hashData` as the data to be signed using the private key specified by `privateKeyBytes`. `proofBytes` will be
  //    exactly 64 bytes in size for a P-256 key, and 96 bytes in size for a P-384 key.
  // 3. Return `proofBytes` as the digital proof.

  const method = await document.retrieveVerificationMethod(
    options.proof.verificationMethod!,
    new Set(),
    { documentLoader: options.documentLoader },
  )
  const keypair = await ECKeypair.import(method, { curve: options.curve })
  if (!keypair.privateKey) {
    throw new ProcessingError(
      ProcessingErrorCode.INVALID_VERIFICATION_METHOD,
      "suite/core#serializeRdfcJcs",
      "The specified verification method does not contain a private key.",
    )
  }

  let hashName: string
  if (options.curve === Curve.P256) {
    hashName = "SHA-256"
  } else if (options.curve === Curve.P384) {
    hashName = "SHA-384"
  } else {
    throw new ProcessingError(
      ProcessingErrorCode.PROOF_GENERATION_ERROR,
      "suite/core#serializeRdfcJcs",
      `The specified ${options.curve} curve is not supported.`,
    )
  }

  const proofBytes = await crypto.subtle.sign(
    { name: SUITE_CONSTANT.ALGORITHM, hash: { name: hashName } },
    keypair.privateKey,
    hashData,
  )
  return new Uint8Array(proofBytes)
}

/**
 * Verify a digital signature from a set of cryptographic hash data.
 *
 * @param {Uint8Array} hashData A cryptographic hash data to be verified.
 * @param {Uint8Array} proofBytes A digital proof to verify.
 * @param {object} options A set of options to use when verifying the digital proof.
 *
 * @returns {Promise<boolean>} Resolve to a verification result.
 *
 * @see https://www.w3.org/TR/vc-di-ecdsa/#proof-verification-ecdsa-rdfc-2019
 * @see https://www.w3.org/TR/vc-di-ecdsa/#proof-verification-ecdsa-jcs-2019
 */
export async function verifyRdfcJcs(
  hashData: Uint8Array,
  proofBytes: Uint8Array,
  options: {
    curve: Curve
    proof: Proof
    documentLoader: LoadDocumentCallback
  },
): Promise<boolean> {
  // Procedure:
  //
  // 1. Let `publicKeyBytes` be the result of retrieving the public key bytes associated with the
  //    `options.verificationMethod` value.
  // 2. Let `verificationResult` be the result of applying the verification algorithm for the Elliptic Curve Digital
  //    Signature Algorithm (ECDSA), with `hashData` as the data to be verified against the `proofBytes` using the
  //    public key specified by `publicKeyBytes`.
  // 3. Return `verificationResult` as the verification result.

  const method = await document.retrieveVerificationMethod(
    options.proof.verificationMethod!,
    new Set(),
    { documentLoader: options.documentLoader },
  )
  const keypair = await ECKeypair.import(method, { curve: options.curve })
  if (!keypair.publicKey) {
    throw new ProcessingError(
      ProcessingErrorCode.INVALID_VERIFICATION_METHOD,
      "suite/core#verifyRdfcJcs",
      "The specified verification method does not contain a public key.",
    )
  }

  let hashName: string
  if (options.curve === Curve.P256) {
    hashName = "SHA-256"
  } else if (options.curve === Curve.P384) {
    hashName = "SHA-384"
  } else {
    throw new ProcessingError(
      ProcessingErrorCode.PROOF_GENERATION_ERROR,
      "suite/core#verifyRdfcJcs",
      `The specified ${options.curve} curve is not supported.`,
    )
  }

  const result = await crypto.subtle.verify(
    { name: SUITE_CONSTANT.ALGORITHM, hash: { name: hashName } },
    keypair.publicKey,
    proofBytes,
    hashData,
  )
  return result
}

/**
 * Transform an unsecured input document into a transformed document that is ready to be provided as input to the
 * hashing algorithm.
 *
 * @param {Credential} unsecuredDocument An unsecured input document to transform.
 * @param {object} options A set of options to use when transforming the document. The transformation options MUST
 * contain a type identifier `type` for the cryptographic suite, a cryptosuite identifier `cryptosuite`, and a
 * verification method `verificationMethod`. The transformation options MUST contain an array of mandatory JSON pointers
 * `mandatoryPointers`, and MAY contain additional options, such as a JSON-LD document loader.
 *
 * @returns {Promise<TransformedDocument>} Resolve to a transformed data document, which is a map containing the
 * mandatory pointers, mandatory revealed values, non-mandatory revealed values, and the HMAC key.
 *
 * @see https://www.w3.org/TR/vc-di-ecdsa/#base-proof-transformation-ecdsa-sd-2023
 */
export async function transformSd(
  unsecuredDocument: Credential,
  options:
    & {
      curve: Curve
      proof: Proof
      mandatoryPointers: Array<string>
      documentLoader: LoadDocumentCallback
      urnScheme?: URNScheme
      randomString?: string
    }
    & Expand
    & Compact
    & ToRdf
    & Partial<Canonize>,
): Promise<TransformedDocument> {
  // Procedure:
  //
  // 1. Initialize `hmac` to an HMAC API using a locally generated and exportable HMAC key. The HMAC uses the same hash
  //    algorithm used in the signature algorithm, which is detected via the `verificationMethod` provided to the
  //    function, i.e., SHA-256 for a P-256 curve. Per the recommendations of [RFC-2104], the HMAC key MUST be the same
  //    length as the digest size; for SHA-256, this is 256 bits or 32 bytes.
  // 2. Initialize `labelMapFactoryFunction` to the result of calling the `createHmacIdLabelMapFunction` function,
  //    passing `hmac`.
  // 3. Initialize `groupDefinitions` to a map with an entry with a key of the string `mandatory` and a value of
  //    `mandatoryPointers`.
  // 4. Initialize `groups` to the result of calling the `canonicalizeAndGroup` function, passing
  //    `labelMapFactoryFunction`, `groupDefinitions`, `unsecuredDocument` as `document`, and any custom JSON-LD API
  //    options. Note: This step transforms the document into an array of canonical N-Quads with pseudorandom blank node
  //    identifiers based on `hmac`, and groups the N-Quad strings according to selections based on JSON pointers.
  // 5. Initialize `mandatory` to the values in the `groups.mandatory.matching` map.
  // 6. Initialize `nonMandatory` to the values in the `groups.mandatory.nonMatching` map.
  // 7. Initialize `hmacKey` to the result of exporting the HMAC key from `hmac`.
  // 8. Return an object with `mandatoryPointers` set to `mandatoryPointers`, `mandatory` set to `mandatory`,
  //    `nonMandatory` set to `nonMandatory`, and `hmacKey` set to `hmacKey`.

  if (
    options.proof.type !== SUITE_CONSTANT.GENERAL_PROOF_TYPE ||
    options.proof.cryptosuite !== SUITE_CONSTANT.SUITE_SD
  ) {
    throw new ProcessingError(
      ProcessingErrorCode.PROOF_TRANSFORMATION_ERROR,
      "suite/core#transformSd",
      "The proof type or cryptosuite is not supported.",
    )
  }

  const hmacCryptoKey = await crypto.subtle.generateKey(
    { name: "HMAC", hash: options.curve },
    true,
    ["sign", "verify"],
  )
  const hmac: HMAC = async (data: Uint8Array) =>
    new Uint8Array(await crypto.subtle.sign(hmacCryptoKey.algorithm, hmacCryptoKey, data))
  const labelMapFactoryFunction = selective.createHmacIdLabelMapFunction(hmac)

  const groupDefinitions: Map<string, Array<string>> = new Map([
    ["mandatory", options.mandatoryPointers],
  ])
  const { groups } = await selective.canonicalizeAndGroup(
    unsecuredDocument,
    labelMapFactoryFunction,
    groupDefinitions,
    options,
  )

  const mandatory = groups.get("mandatory")?.matching!
  const nonMandatory = groups.get("mandatory")?.nonMatching!
  const hmacKey = new Uint8Array(await crypto.subtle.exportKey("raw", hmacCryptoKey))

  const transformedDocument = {
    mandatoryPointers: options.mandatoryPointers,
    mandatory,
    nonMandatory,
    hmacKey,
  }
  return transformedDocument
}

/**
 * Generate a proof configuration from a set of proof options that is used as input to the proof hashing algorithm.
 *
 * @param {Credential} unsecuredDocument An unsecured input document to generate a proof configuration from.
 * @param {object} options A set of proof options to generate a proof configuration from. The proof options MUST contain
 * a type identifier `type` for the cryptographic suite and a cryptosuite identifier `cryptosuite`.
 *
 * @returns {Promise<string>} Resolve to a proof configuration.
 *
 * @see https://www.w3.org/TR/vc-di-ecdsa/#base-proof-configuration-ecdsa-sd-2023
 */
export async function configSd(
  unsecuredDocument: Credential,
  options: {
    proof: Proof
    documentLoader: LoadDocumentCallback
  },
): Promise<string> {
  // Procedure:
  //
  // 1. Let `proofConfig` be a clone of the `options` object.
  // 2. If `proofConfig.type` is not set to `DataIntegrityProof` and/or `proofConfig.cryptosuite` is not set to
  //    `ecdsa-sd-2023`, an error MUST be raised and SHOULD convey an error type of `PROOF_GENERATION_ERROR`.
  // 3. If `proofConfig.created` is set and if the value is not a valid datetime, an error MUST be raised and SHOULD
  //    convey an error type of `PROOF_GENERATION_ERROR`.
  // 4. Set `proofConfig.@context` to `unsecuredDocument.@context`.
  // 5. Let `canonicalProofConfig` be the result of applying the RDF Dataset Canonicalization Algorithm to the
  //    `proofConfig`.
  // 6. Return `canonicalProofConfig`.

  const proofConfig = structuredClone(options.proof)

  if (proofConfig.type !== SUITE_CONSTANT.GENERAL_PROOF_TYPE || proofConfig.cryptosuite !== SUITE_CONSTANT.SUITE_SD) {
    throw new ProcessingError(
      ProcessingErrorCode.PROOF_GENERATION_ERROR,
      "suite/core#configSd",
      "The proof type or cryptosuite is not supported.",
    )
  }

  if (proofConfig.created && !Date.parse(proofConfig.created)) {
    throw new ProcessingError(
      ProcessingErrorCode.PROOF_GENERATION_ERROR,
      "suite/core#configSd",
      "The proof creation date is not a valid datetime.",
    )
  }

  proofConfig["@context"] = unsecuredDocument["@context"]

  const canonicalProofConfig = await rdfc.normalize(proofConfig, {
    algorithm: "URDNA2015",
    format: "application/n-quads",
    documentLoader: options.documentLoader,
  })

  return canonicalProofConfig
}

/**
 * Cryptographically hash a transformed data document and proof configuration into cryptographic hash data that is
 * ready to be provided as input to the proof serialization algorithm.
 *
 * @param {TransformedDocument} transformedDocument A transformed data document to be hashed.
 * @param {string} canonicalProofConfig A canonical proof configuration.
 * @param {object} options A set of options to use when hashing the transformed data document and proof configuration.
 * The options MUST contain a curve identifier `curve` indicating the security level to use.
 *
 * @returns {Promise<HashData>} Resolve to a cryptographic hash data.
 *
 * @see https://www.w3.org/TR/vc-di-ecdsa/#base-proof-hashing-ecdsa-sd-2023
 */
export async function hashSd(
  transformedDocument: TransformedDocument,
  canonicalProofConfig: string,
  options: {
    curve: Curve
  },
): Promise<HashData> {
  // Procedure:
  //
  // 1. Initialize `proofHash` to the result of calling the RDF Dataset Canonicalization algorithm on
  //    `canonicalProofConfig` and then cryptographically hashing the result using the same hash that is used by the
  //    signature algorithm, i.e., SHA-256 for a P-256 curve. Note: This step can be performed in parallel; it only
  //    needs to be completed before this algorithm terminates as the result is part of the return value.
  // 2. Initialize `mandatoryHash` to the result of calling the `hashMandatoryNQuads` function, passing
  //    `transformedDocument.mandatory`.
  // 3. Initialize `hashData` as a deep copy of `transformedDocument` and add `proofHash` as `proofHash` and
  //    `mandatoryHash` as `mandatoryHash` to that object.
  // 4. Return `hashData` as hash data.

  const hasher = constructHasher(options.curve)
  const proofHash = await hasher(new TextEncoder().encode(canonicalProofConfig))
  const mandatory = [...transformedDocument.mandatory.values()]
  const mandatoryHash = await selective.hashMandatoryNQuads(mandatory, hasher)
  const clonedDocument = structuredClone(transformedDocument)
  return {
    ...clonedDocument,
    proofHash,
    mandatoryHash,
  }
}

/**
 * Create a base proof. This function will be called by an issuer of an ECDSA-SD-protected verifiable credential. The
 * base proof is to be given only to the holder, who is responsible for generating a derived proof from it, exposing
 * only selectively disclosed details in the proof to a verifier.
 *
 * @param {HashData} hashData A cryptographic hash data to serialize.
 * @param {object} options A set of options to use when serializing the hash data. The proof options MUST contain a type
 * identifier `type` for the cryptographic suite, and MAY contain a cryptosuite identifier `cryptosuite`.
 *
 * @returns {Promise<string>} Resolve to a serialized digital proof.
 *
 * @see https://www.w3.org/TR/vc-di-ecdsa/#base-proof-serialization-ecdsa-sd-2023
 */
export async function serializeSd(
  hashData: HashData,
  options: {
    curve: Curve
    proof: Proof
    documentLoader: LoadDocumentCallback
  },
): Promise<string> {
  // Procedure:
  //
  // 1. Initialize `proofHash`, `mandatoryPointers`, `mandatoryHash`, `nonMandatory`, and `hmacKey` to the values
  //    associated with their property names `hashData`.
  // 2. Initialize `proofScopedKeyPair` to a locally generated P-256 ECDSA keypair. Note: This keypair is scoped to the
  //    specific proof; it is not used for anything else and the private key will be destroyed when this algorithm
  //    terminates.
  // 3. Initialize `signatures` to an array where each element holds the result of digitally signing the UTF-8
  //    representation of each N-Quad string in `nonMandatory`, in order. The digital signature algorithm is ES256,
  //    i.e., uses a P-256 curve over a SHA-256 digest, and uses the private key from `proofScopedKeyPair`. Note: This
  //    step generates individual signatures for each statement that can be selectively disclosed using a local, proof-
  //    scoped keypair that binds them together; this keypair will be bound to the proof by a signature over its public
  //    key using the private key associated with the base proof verification method.
  // 4. Initialize `publicKey` to the multikey expression of the public key exported from `proofScopedKeyPair`. That is,
  //    an array of bytes starting with the bytes `0x80` and `0x24` (which is the multikey p256-pub header `0x1200`
  //    expressed as a varint) followed by the compressed public key bytes (the compressed header with 2 for an even y
  //    coordinate and 3 for an odd one followed by the x coordinate of the public key).
  // 5. Initialize `toSign` to the result of calling the `serializeSignData` function, passing `proofHash`, `publicKey`,
  //    and `mandatoryHash` as parameters to the algorithm.
  // 6. Initialize `baseSignature` to the result of digitally signing `toSign` using the private key associated with the
  //    base proof verification method.
  // 7. Initialize `proofValue` to the result of calling the `serializeBaseProofValue` function, passing
  //    `baseSignature`, `publicKey`, `hmacKey`, `signatures`, and `mandatoryPointers` as parameters to the algorithm.
  // 8. Return `proofValue` as digital proof.

  const { proofHash, mandatoryHash, mandatoryPointers, nonMandatory, hmacKey } = hashData

  const proofScopedKeyPair = new ECKeypair(Curve.P256)
  await proofScopedKeyPair.initialize()

  const signatures = await Promise.all([...nonMandatory.values()].map(async (nQuad) => {
    const signature = await crypto.subtle.sign(
      { name: SUITE_CONSTANT.ALGORITHM, hash: "SHA-256" },
      proofScopedKeyPair.privateKey!,
      new TextEncoder().encode(nQuad),
    )
    return new Uint8Array(signature)
  }))

  const publicKeyMaterial = await keyToMaterial(proofScopedKeyPair.publicKey!, "public", options.curve)
  const publicKeyMultibase = materialToMultibase(publicKeyMaterial, "public", options.curve)
  const publicKey = multi.base58btc.decode(publicKeyMultibase)
  const toSign = serializeSignData(proofHash, publicKey, mandatoryHash)

  const method = await document.retrieveVerificationMethod(options.proof.verificationMethod!, new Set(), {
    documentLoader: options.documentLoader,
  })
  const keypair = await ECKeypair.import(method, { curve: options.curve })
  if (!keypair.privateKey) {
    throw new ProcessingError(
      ProcessingErrorCode.INVALID_VERIFICATION_METHOD,
      "suite/core#serializeSd",
      "The specified verification method does not contain a private key.",
    )
  }

  let hashName: string
  if (options.curve === Curve.P256) {
    hashName = "SHA-256"
  } else if (options.curve === Curve.P384) {
    hashName = "SHA-384"
  } else {
    throw new ProcessingError(
      ProcessingErrorCode.PROOF_GENERATION_ERROR,
      "suite/core#serializeSd",
      `The specified ${options.curve} curve is not supported.`,
    )
  }

  const baseSignatureBytes = await crypto.subtle.sign(
    { name: SUITE_CONSTANT.ALGORITHM, hash: hashName },
    keypair.privateKey,
    toSign,
  )
  const baseSignature = new Uint8Array(baseSignatureBytes)

  return serializeBaseProofValue({
    baseSignature,
    publicKey,
    hmacKey,
    signatures,
    mandatoryPointers,
  })
}

/**
 * Create a selective disclosure derived proof. This function will be called by a holder of an ECDSA-SD-protected
 * verifiable credential. The derived proof is to be given to a verifier, who can use it to verify the proof and the
 * disclosed details.
 *
 * @param {Credential} document A verifiable credential to derive a selective disclosure proof from.
 * @param {} proof A base proof to derive a selective disclosure proof from.
 * @param {Array<string>} selectivePointers An array of JSON pointers to the properties to selectively disclose.
 * @param {object} options A set of options to use when deriving the selective disclosure proof.
 *
 * @see https://www.w3.org/TR/vc-di-ecdsa/#add-derived-proof-ecdsa-sd-2023
 */
export async function deriveSd(
  document: Credential,
  proof: Proof,
  selectivePointers: Array<string>,
  options:
    & {
      curve: Curve
      urnScheme?: URNScheme
      randomString?: string
      documentLoader: LoadDocumentCallback
    }
    & Expand
    & Compact
    & ToRdf
    & Partial<Canonize>,
): Promise<Proof> {
  // Procedure:
  //
  // 1. Initialize `baseSignature`, `publicKey`, `signatures`, `labelMap`, `mandatoryIndexes`, `revealDocument` to the
  //    values associated with their property names in the object returned when calling the `createDisclosureData`
  //    function, passing the `document`, `proof`, `selectivePointers`, and any custom JSON-LD API options, such as a
  //    document loader.
  // 2. Initialize `newProof` to a shallow copy of `proof`.
  // 3. Replace `proofValue` in `newProof` with the result of calling the `serializeDerivedProofValue` function, passing
  //    `baseSignature`, `publicKey`, `signatures`, `labelMap`, and `mandatoryIndexes`.
  // 4. Set the value of the `proof` property in `revealDocument` to `newProof`.
  // 5. Return `revealDocument` as the selectively revealed document.

  const {
    baseSignature,
    publicKey,
    signatures,
    labelMap,
    mandatoryIndexes,
  } = await createDisclosureData(document, proof, selectivePointers, options)
  const newProof = structuredClone(proof)
  newProof.proofValue = serializeDerivedProofValue({
    baseSignature,
    publicKey,
    signatures,
    labelMap,
    mandatoryIndexes,
  })
  return newProof
}

/**
 * Verify a selective disclosed signature.
 *
 * @param {Uint8Array} baseSignature The base signature to verify.
 * @param {Array<Uint8Array>} signatures The selective disclosed signatures to verify.
 * @param {CryptoKey} publicKey The public key to use for verification.
 * @param {object} options A set of options to use when verifying the selective disclosed signature.
 *
 * @see https://www.w3.org/TR/vc-di-ecdsa/#verify-derived-proof-ecdsa-sd-2023
 */
export async function verifySd(
  toVerify: Uint8Array,
  nonMandatory: Array<string>,
  baseSignature: Uint8Array,
  signatures: Array<Uint8Array>,
  publicKey: Uint8Array,
  options: {
    curve: Curve
    proof: Proof
    documentLoader: LoadDocumentCallback
  },
): Promise<boolean> {
  // Procedure:
  //
  // 3. If the length of `signatures` does not match the length of `nonMandatory`, an error MUST be raised and SHOULD
  //    convey an error type of `PROOF_VERIFICATION_ERROR`, indicating that the signature count does not match the
  //    non-mandatory message count.
  // 4. Initialize `publicKeyBytes` to the public key bytes expressed in `publicKey`.
  // 6. Initialize `verified` to `true`.
  // 7. Initialize `verificationCheck` be the result of applying the verification algorithm of the Elliptic Curve
  //    Digital Signature Algorithm (ECDSA) [FIPS-186-5], with `toVerify` as the data to be verified against the
  //    `baseSignature` using the public key. If `verificationCheck` is `false`, set `verified` to `false`.
  // 8. For every entry (`index`, `signature`) in `signatures`, verify every `signature` for every selectively disclosed
  //    (non-mandatory) statement:
  //
  //    8.1. Initialize `verificationCheck` to the result of applying the verification algorithm Elliptic Curve Digital
  //         Signature Algorithm (ECDSA) [FIPS-186-5], with the UTF-8 representation of the value at `index` of
  //         `nonMandatory` as the data to be verified against `signature` using the public key.
  //    8.2. If `verificationCheck` is `false`, set `verified` to `false`.
  //
  // 9. Return `verified` as the verification result.

  if (signatures.length !== nonMandatory.length) {
    throw new ProcessingError(
      ProcessingErrorCode.PROOF_VERIFICATION_ERROR,
      "suite/core#verifySd",
      `The signature count ${signatures.length} does not match the non-mandatory message count ${nonMandatory.length}.`,
    )
  }

  const method = await document.retrieveVerificationMethod(
    options.proof.verificationMethod!,
    new Set(),
    { documentLoader: options.documentLoader },
  )
  const keypair = await ECKeypair.import(method, { curve: options.curve })
  if (!keypair.publicKey) {
    throw new ProcessingError(
      ProcessingErrorCode.INVALID_VERIFICATION_METHOD,
      "suite/core#verifySd",
      "The specified verification method does not contain a public key.",
    )
  }

  let hashName: string
  if (options.curve === Curve.P256) {
    hashName = "SHA-256"
  }
  if (options.curve === Curve.P384) {
    hashName = "SHA-384"
  } else {
    throw new ProcessingError(
      ProcessingErrorCode.PROOF_GENERATION_ERROR,
      "suite/core#verifySd",
      `The specified ${options.curve} curve is not supported.`,
    )
  }

  let verified: boolean = true
  const verificationCheck = await crypto.subtle.verify(
    { name: SUITE_CONSTANT.ALGORITHM, hash: hashName },
    keypair.publicKey,
    baseSignature,
    toVerify,
  )
  if (!verificationCheck) {
    verified = false
  }

  const publicKeyMultibase = multi.base58btc.encode(publicKey)
  const publicKeyMaterial = multibaseToMaterial(publicKeyMultibase, "public", options.curve)
  const publicCryptoKey = await materialToPublicKey(publicKeyMaterial, options.curve)

  const verificationChecks = await Promise.all(signatures.map((signature, index) =>
    crypto.subtle.verify(
      { name: SUITE_CONSTANT.ALGORITHM, hash: hashName },
      publicCryptoKey,
      signature,
      new TextEncoder().encode(nonMandatory[index]),
    )
  ))

  if (verificationChecks.includes(false)) {
    verified = false
  }

  return verified
}

type TransformedDocument = {
  mandatoryPointers: Array<string>
  mandatory: Map<number, string>
  nonMandatory: Map<number, string>
  hmacKey: Uint8Array
}

type HashData = {
  proofHash: Uint8Array
  mandatoryHash: Uint8Array
} & TransformedDocument
