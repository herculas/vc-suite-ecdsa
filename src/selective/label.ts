import { type LabelMap, multi, ProcessingError, ProcessingErrorCode } from "@herculas/vc-data-integrity"
import * as PREFIX_CONSTANT from "../constant/prefix.ts"
import type { CompressedLabelMap } from "./types.ts"

/**
 * Compress a label map.
 *
 * @param {LabelMap} labelMap A label map to compress.
 *
 * @returns {CompressedLabelMap} A compressed label map.
 *
 * @see https://www.w3.org/TR/vc-di-ecdsa/#compresslabelmap
 */
export function compressLabelMap(labelMap: LabelMap): CompressedLabelMap {
  // Procedure:
  //
  // 1. Initialize `map` to an empty map.
  // 2. For each entry (`k`, `v`) in `labelMap`, do:
  //
  //    2.1. Add an entry to `map` with a key that is a base-10 integer parsed from the characters following the "c14n"
  //         prefix in `k`, and a value that is a byte array resulting from base64url-no-pad-decoding the characters
  //         after the `u` prefix in `v`.
  //
  // 3. Return `map` as compressed label map.

  const map: CompressedLabelMap = new Map()
  for (const [key, value] of labelMap.entries()) {
    if (!key.startsWith(PREFIX_CONSTANT.BLANK_LABEL)) {
      throw new ProcessingError(
        ProcessingErrorCode.PROOF_GENERATION_ERROR,
        "suite/core#compressLabelMap",
        "The label map key is not a valid prefix.",
      )
    }
    const index = parseInt(key.replace(PREFIX_CONSTANT.BLANK_LABEL, ""), 10)
    const data = multi.base64urlnopad.decode(value)
    if (isNaN(index)) {
      throw new ProcessingError(
        ProcessingErrorCode.PROOF_GENERATION_ERROR,
        "suite/core#compressLabelMap",
        "The label map key is not a valid integer.",
      )
    }
    map.set(index, data)
  }
  return map
}

/**
 * Decompress a label map.
 *
 * @param {CompressedLabelMap} compressedLabelMap A compressed label map.
 *
 * @returns {LabelMap} A decompressed label map.
 *
 * @see https://www.w3.org/TR/vc-di-ecdsa/#decompresslabelmap
 */
export function decompressLabelMap(compressedLabelMap: CompressedLabelMap): LabelMap {
  // Procedure:
  //
  // 1. Initialize `map` to an empty map.
  // 2. For each entry (`k`, `v`) in `compressedLabelMap`, do:
  //
  //    2.1. Add an entry to `map` with a key that adds the prefix "c14n" to `k` and a value that adds a prefix "u" to
  //         the base64url-no-pad-encoded value of `v`.
  //
  // 3. Return `map` as decompressed label map.

  const map: LabelMap = new Map()
  for (const [key, value] of compressedLabelMap.entries()) {
    const index = `${PREFIX_CONSTANT.BLANK_LABEL}${key}`
    const data = multi.base64urlnopad.encode(value)
    map.set(index, data)
  }
  return map
}
