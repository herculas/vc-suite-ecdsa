import {
  type Credential,
  document,
  format,
  type Loader,
  ProcessingError,
  ProcessingErrorCode,
  type Proof,
  rdfc,
} from "@herculas/vc-data-integrity"

import { Curve } from "../constant/curve.ts"
import { ECKeypair } from "../key/keypair.ts"
import { sha256, sha384 } from "../utils/crypto.ts"

import * as SUITE_CONSTANT from "../constant/suite.ts"

/**
 * Transform an unsecured input document into a transformed document that is ready to be provided as input to the
 * hashing algorithm.
 *
 * @param {Credential} unsecuredDocument An unsecured input document to transform.
 * @param {object} options A set of options to use when transforming the document.
 *
 * @returns {Promise<string>} Resolve to a transformed data document.
 *
 * @see https://www.w3.org/TR/vc-di-ecdsa/#transformation-ecdsa-rdfc-2019
 */
export async function transformRdfc(
  unsecuredDocument: Credential,
  options: {
    proof: Proof
    documentLoader: Loader
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
      "suite/core#transformRDFC",
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
 * @param {object} options A set of proof options to generate a proof configuration from.
 *
 * @returns {Promise<string>} Resolve to a proof configuration.
 *
 * @see https://www.w3.org/TR/vc-di-ecdsa/#proof-configuration-ecdsa-rdfc-2019
 */
export async function configRdfc(
  unsecuredDocument: Credential,
  options: {
    proof: Proof
    documentLoader: Loader
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
      "suite/core#configRDFC",
      "The proof type or cryptosuite is not supported.",
    )
  }

  if (proofConfig.created && !Date.parse(proofConfig.created)) {
    throw new ProcessingError(
      ProcessingErrorCode.PROOF_GENERATION_ERROR,
      "suite/core#configRDFC",
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
 * ready to be provided as input to the proof serialization algorithm and proof verification algorithm.
 *
 * One must use the hash algorithm appropriate in security level to the curve used, i.e., for curve P-256 one uses
 * SHA-256 and for curve P-384 one uses SHA-384.
 *
 * @param {string} transformedDocument A transformed data document to be hashed.
 * @param {string} canonicalProofConfig A canonical proof configuration.
 * @param {Curve} curve A elliptic curve, either P-256 or P-384, indicating the security level to use.
 *
 * @returns {Promise<Uint8Array>} Resolve to a single hash data represented as series of bytes.
 *
 * @see https://www.w3.org/TR/vc-di-ecdsa/#hashing-ecdsa-rdfc-2019
 */
export async function hash(
  transformedDocument: string,
  canonicalProofConfig: string,
  curve: Curve,
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

  let hash: (data: string) => Promise<Uint8Array>
  if (curve === Curve.P256) {
    hash = sha256
  } else if (curve === Curve.P384) {
    hash = sha384
  } else {
    throw new ProcessingError(
      ProcessingErrorCode.PROOF_GENERATION_ERROR,
      "suite/core#hash",
      `The specified ${curve} curve is not supported.`,
    )
  }

  const proofConfigHash = await hash(canonicalProofConfig)
  const transformedDocumentHash = await hash(transformedDocument)
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
 */
export async function serialize(
  hashData: Uint8Array,
  options: {
    curve: Curve
    proof: Proof
    documentLoader: Loader
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

  const method = await document.retrieveVerificationMethod(options.proof.verificationMethod!, new Set(), {
    documentLoader: options.documentLoader,
  })
  const keypair = await ECKeypair.import(method, { curve: options.curve })
  if (!keypair.privateKey) {
    throw new ProcessingError(
      ProcessingErrorCode.INVALID_VERIFICATION_METHOD,
      "suite/core#serialize",
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
      "suite/core#hash",
      `The specified ${options.curve} curve is not supported.`,
    )
  }

  const proofBytes = await crypto.subtle.sign(
    { name: "ECDSA", hash: { name: hashName } },
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
 */
export async function verify(
  hashData: Uint8Array,
  proofBytes: Uint8Array,
  options: {
    curve: Curve
    proof: Proof
    documentLoader: Loader
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

  const method = await document.retrieveVerificationMethod(options.proof.verificationMethod!, new Set(), {
    documentLoader: options.documentLoader,
  })
  const keypair = await ECKeypair.import(method, { curve: options.curve })
  if (!keypair.publicKey) {
    throw new ProcessingError(
      ProcessingErrorCode.INVALID_VERIFICATION_METHOD,
      "suite/core#verify",
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
      "suite/core#hash",
      `The specified ${options.curve} curve is not supported.`,
    )
  }

  const result = await crypto.subtle.verify(
    { name: "ECDSA", hash: { name: hashName } },
    keypair.publicKey,
    proofBytes,
    hashData,
  )
  return result
}
