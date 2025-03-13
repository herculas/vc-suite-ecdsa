import { assert } from "@std/assert"
import { isString, isUint8Array } from "../utils/guard.ts"
import type { BaseProofValue, CompressedProofValue } from "./types.ts"

export function assertBaseProofValue(components: unknown): BaseProofValue {
  assert(Array.isArray(components) && components.length === 5)
  assert(isUint8Array(components[0], 64) || isUint8Array(components[0], 96))
  assert(isUint8Array(components[1], 35))
  assert(isUint8Array(components[2], 32))
  assert(Array.isArray(components[3]) && components[3].every((signature) => isUint8Array(signature, 64)))
  assert(Array.isArray(components[4]) && components[4].every(isString))
  return {
    baseSignature: components[0],
    publicKey: components[1],
    hmacKey: components[2],
    signatures: components[3],
    mandatoryPointers: components[4],
  }
}

export function assertCompressedProofValue(components: unknown): CompressedProofValue {
  assert(Array.isArray(components) && components.length === 5)
  assert(isUint8Array(components[0], 64) || isUint8Array(components[0], 96))
  assert(isUint8Array(components[1], 35))
  assert(Array.isArray(components[2]) && components[2].every((signature) => isUint8Array(signature)))
  assert(
    components[3] instanceof Map &&
      components[3].entries().every(([key, value]) => Number.isInteger(key) && isUint8Array(value)),
  )
  assert(Array.isArray(components[4]) && components[4].every(Number.isInteger))
  return {
    baseSignature: components[0],
    publicKey: components[1],
    signatures: components[2],
    compressedLabelMap: components[3],
    mandatoryIndexes: components[4],
  }
}
