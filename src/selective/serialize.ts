import * as cbor from "cbor2"
import { format, multi, ProcessingError, ProcessingErrorCode } from "@herculas/vc-data-integrity"

import { assertBaseProofValue, assertCompressedProofValue } from "./assert.ts"
import { compressLabelMap, decompressLabelMap } from "./label.ts"

import type { BaseProofValue, DerivedProofValue } from "./types.ts"

import * as PREFIX_CONSTANT from "../constant/prefix.ts"

/**
 * Serialize the base proof value, including the base signature, the public key, the HMAC key, the signatures, and the
 * mandatory pointers.
 *
 * @param {BaseProofValue} proofValue A single object containing five components using the names `baseSignature`,
 * `publicKey`, `hmacKey`, `signatures`, and `mandatoryPointers`.
 *
 * @returns {string} A serialized base proof value.
 *
 * @see https://www.w3.org/TR/vc-di-ecdsa/#serializebaseproofvalue
 */
export function serializeBaseProofValue(proofValue: BaseProofValue): string {
  // Procedure:
  //
  // 1. Initialize a byte array, `proofValue`, that starts with the ECDSA-SD base proof header bytes `0xd9`, `0x5d`, and
  //    `0x00`.
  // 2. Initialize components to an array with five elements containing the values of: `baseSignature`, `publicKey`,
  //    `hmacKey`, `signatures`, and `mandatoryPointers`.
  // 3. CBOR-encode the components per [RFC-8949] where CBOR tagging MUST NOT be used on any of the components. Append
  //    the produced encoded value to `proofValue`.
  // 4. Initialize `baseProof` to a string with the Multibase base64url-no-pad-encoding of `proofValue`. That is, return
  //    a string starting with `u` and ending with the base64url-no-pad-encoded value of `proofValue`.
  // 5. Return `baseProof` as the base proof.

  const components = [
    proofValue.baseSignature,
    proofValue.publicKey,
    proofValue.hmacKey,
    proofValue.signatures,
    proofValue.mandatoryPointers,
  ]
  assertBaseProofValue(components)

  const prefix = format.hexToBytes(PREFIX_CONSTANT.CBOR_BASE)
  const proofValueBytes = format.concatenate(prefix, cbor.encode(components))
  const baseProof = multi.base64urlnopad.encode(proofValueBytes)
  return baseProof
}

/**
 * Serialize a derived proof value.
 *
 * @param {DerivedProofValue} proofValue A single object containing five components using the names `baseSignature`,
 * `publicKey`, `signatures`, `labelMap`, and `mandatoryIndexes`.
 *
 * @see https://www.w3.org/TR/vc-di-ecdsa/#serializederivedproofvalue
 */
export function serializeDerivedProofValue(proofValue: DerivedProofValue): string {
  // Procedure:
  //
  // 1. Initialize `compressedLabelMap` to the result of calling the `compressLabelMap` function, passing `labelMap` as
  //    the parameter.
  // 2. Initialize a byte array, `proofValue`, that starts with the ECDSA-SD disclosure proof header bytes `0xd9`,
  //    `0x5d`, and `0x01`.
  // 3. Initialize `components` to an array with five elements containing the values of: `baseSignature`, `publicKey`,
  //    `signatures`, `compressedLabelMap`, and `mandatoryIndexes`.
  // 4. CBOR-encode `components` per [RFC8949] where CBOR tagging MUST NOT be used on any of the components. Append the
  //    produced encoded value to `proofValue`.
  // 5. Return the `derivedProof` as a string with the base64url-no-pad-encoding of `proofValue`. That is, return a
  //    string starting with "u" and ending with the base64url-no-pad-encoded value of `proofValue`.

  const compressedLabelMap = compressLabelMap(proofValue.labelMap)
  const components = [
    proofValue.baseSignature,
    proofValue.publicKey,
    proofValue.signatures,
    compressedLabelMap,
    proofValue.mandatoryIndexes,
  ]
  assertCompressedProofValue(components)

  const prefix = format.hexToBytes(PREFIX_CONSTANT.CBOR_DERIVED)
  const proofValueBytes = format.concatenate(prefix, cbor.encode(components))
  const derivedProof = multi.base64urlnopad.encode(proofValueBytes)
  return derivedProof
}

/**
 * Parse the components of an ecdsa-sd-2023 selective disclosure base proof value.
 *
 * @param {string} proofValue A proof value encoded as a base64url-no-pad string.
 *
 * @returns {BaseProofValue} A single object parsed base proof, containing five components using the names
 * `baseSignature`, `publicKey`, `hmacKey`, `signatures`, and `mandatoryPointers`.
 *
 * @see https://www.w3.org/TR/vc-di-ecdsa/#parsebaseproofvalue
 */
export function parseBaseProofValue(proofValue: string): BaseProofValue {
  // Procedure:
  //
  // 1. If the `proofValue` string does not start with `u`, indicating that it is a multibase-base64url-no-pad-encoded
  //    value, an error MUST be raised and SHOULD convey an error type of `PROOF_VERIFICATION_ERROR`.
  // 2. Initialize `decodedProofValue` to the result of `base64url-no-pad-decoding` the substring after the leading `u`
  //    in `proofValue`.
  // 3. If the `decodedProofValue` does not start with the ECDSA-SD base proof header bytes `0xd9`, `0x5d`, and `0x00`,
  //    an error MUST be raised and SHOULD convey an error type of `PROOF_VERIFICATION_ERROR`.
  // 4. Initialize `components` to an array that is the result of CBOR-decoding the bytes that follow the three-byte
  //    ECDSA-SD base proof header. Confirm that the result is an array of five elements.
  // 5. Return an object with properties set to the five elements, using the names `baseSignature`, `publicKey`,
  //    `hmacKey`, `signatures`, and `mandatoryPointers`, respectively.

  let decodedProofValue: Uint8Array
  try {
    decodedProofValue = multi.base64urlnopad.decode(proofValue)
  } catch {
    throw new ProcessingError(
      ProcessingErrorCode.PROOF_VERIFICATION_ERROR,
      "suite/core#parseBaseProofValue",
      "The proof value is not a valid base64url-no-pad string.",
    )
  }

  const baseHeader = format.hexToBytes(PREFIX_CONSTANT.CBOR_BASE)
  const realHeader = decodedProofValue.slice(0, baseHeader.length)
  if (!realHeader.every((byte, index) => byte === baseHeader[index])) {
    throw new ProcessingError(
      ProcessingErrorCode.PROOF_VERIFICATION_ERROR,
      "suite/core#parseBaseProofValue",
      "The proof value does not contain the correct base proof header.",
    )
  }

  try {
    const components = cbor.decode(decodedProofValue.slice(baseHeader.length))
    return assertBaseProofValue(components)
  } catch {
    throw new ProcessingError(
      ProcessingErrorCode.PROOF_VERIFICATION_ERROR,
      "suite/core#parseBaseProofValue",
      "The proof value is not a valid CBOR-encoded array.",
    )
  }
}

/**
 * Parse the components of a derived proof value.
 *
 * @param {string} proofValue A proof value encoded as a base64url-no-pad string.
 *
 * @returns {object} A single object parsed derived proof, containing a set of five components, using the names
 * `baseSignature`, `publicKey`, `signatures`, `labelMap`, and `mandatoryIndexes`.
 *
 * @see https://www.w3.org/TR/vc-di-ecdsa/#parsederivedproofvalue
 */
export function parseDerivedProofValue(proofValue: string): DerivedProofValue {
  // Procedure:
  //
  // 1. If the `proofValue` string does not start with `u`, an error MUST be raised and SHOULD convey an error type of
  //    `PROOF_VERIFICATION_ERROR`.
  // 2. Initialize `decodedProofValue` to the result of base64url-no-pad-decoding the substring after the leading `u` in
  //    `proofValue`.
  // 3. If the `decodedProofValue` does not start with the ECDSA-SD disclosure proof header bytes `0xd9`, `0x5d`, and
  //    `0x01`, an error MUST be raised and SHOULD convey an error type of `PROOF_VERIFICATION_ERROR`.
  // 4. Initialize `components` to an array that is the result of CBOR-decoding the bytes that follow the three-byte
  //    ECDSA-SD disclosure proof header. If the result is not an array of the following five elements — a byte array of
  //    length 64; a byte array of length 36; an array of byte arrays, each of length 64; a map of integers to byte
  //    arrays, each of length 32; and an array of integers — an error MUST be raised and SHOULD convey an error type of
  //    `PROOF_VERIFICATION_ERROR`.
  // 5. Replace the fourth element in `components` using the result of calling the `decompressLabelMap` function,
  //    passing the existing fourth element of `components` as `compressedLabelMap`.
  // 6. Return `derivedProofValue` as an object with properties set to the five elements, using the names
  //    `baseSignature`, `publicKey`, `signatures`, `labelMap`, and `mandatoryIndexes`, respectively.

  let decodedProofValue: Uint8Array
  try {
    decodedProofValue = multi.base64urlnopad.decode(proofValue)
  } catch {
    throw new ProcessingError(
      ProcessingErrorCode.PROOF_VERIFICATION_ERROR,
      "suite/core#parseBaseProofValue",
      "The proof value is not a valid base64url-no-pad string.",
    )
  }

  const derivedHeader = format.hexToBytes(PREFIX_CONSTANT.CBOR_DERIVED)
  const realHeader = decodedProofValue.slice(0, derivedHeader.length)
  if (!realHeader.every((byte, index) => byte === derivedHeader[index])) {
    throw new ProcessingError(
      ProcessingErrorCode.PROOF_VERIFICATION_ERROR,
      "suite/core#parseBaseProofValue",
      "The proof value does not contain the correct base proof header.",
    )
  }

  try {
    const components = cbor.decode(decodedProofValue.slice(derivedHeader.length))
    const {
      baseSignature,
      publicKey,
      signatures,
      compressedLabelMap,
      mandatoryIndexes,
    } = assertCompressedProofValue(components)
    return {
      baseSignature,
      publicKey,
      signatures,
      labelMap: decompressLabelMap(compressedLabelMap),
      mandatoryIndexes,
    }
  } catch {
    throw new ProcessingError(
      ProcessingErrorCode.PROOF_VERIFICATION_ERROR,
      "suite/core#parseBaseProofValue",
      "The proof value is not a valid CBOR-encoded array.",
    )
  }
}
