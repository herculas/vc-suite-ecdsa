import {
  base64url,
  format,
  ImplementationError,
  ImplementationErrorCode,
  type JWK,
  type JWKEC,
  type KeypairOptions,
} from "@herculas/vc-data-integrity"

import type { Curve } from "../constant/curve.ts"

import * as PREFIX_CONSTANT from "../constant/prefix.ts"
import * as SUITE_CONSTANT from "../constant/suite.ts"

/**
 * Generate an ECDSA keypair using the Web Crypto API.
 *
 * @param {Curve} curve The curve to use for the keypair.
 *
 * @returns {Promise<CryptoKeyPair>} Resolve to an ECDSA keypair.
 */
export async function generateRawKeypair(curve: Curve): Promise<CryptoKeyPair> {
  return await crypto.subtle.generateKey(
    { name: SUITE_CONSTANT.ALGORITHM, namedCurve: curve },
    true,
    ["sign", "verify"],
  )
}

/**
 * Calculate the uncompressed key material from a `CryptoKey` instance. The flag determines if the key is private or
 * public. It should be noted that this operation will remove the DER prefix from the key material.
 *
 * @param {CryptoKey} key A `CryptoKey` instance.
 * @param {KeypairOptions.Flag} flag The flag to determine if the key is private or public.
 *
 * @returns {Promise<Uint8Array>} Resolve to the uncompressed key material.
 */
export async function keyToMaterial(key: CryptoKey, flag: KeypairOptions.Flag): Promise<Uint8Array> {
  const curve = (key.algorithm as EcKeyAlgorithm).namedCurve as Curve
  if (!curve) {
    throw new ImplementationError(
      ImplementationErrorCode.ENCODING_ERROR,
      "keypair/core#keyToMaterial",
      "The key does not have a named curve!",
    )
  }

  const keyFormat = SUITE_CONSTANT.KEY_FORMAT.get(flag)
  const expectedPrefixHex = PREFIX_CONSTANT.DER_UNCOMPRESSED.get(flag)?.get(curve)
  const keyLength = SUITE_CONSTANT.KEY_MATERIAL_LENGTH.get(flag)?.get(curve)

  if (!keyFormat || !expectedPrefixHex || !keyLength) {
    throw new ImplementationError(
      ImplementationErrorCode.ENCODING_ERROR,
      "keypair/core#keyToMaterial",
      `This suite does not support ${curve} curve ${flag} key!`,
    )
  }

  const expectedPrefix = format.hexToBytes(expectedPrefixHex)
  const exportedKey = await crypto.subtle.exportKey(keyFormat, key)
  const realPrefix = new Uint8Array(exportedKey.slice(0, expectedPrefix.length))

  if (!realPrefix.every((byte, index) => byte === expectedPrefix[index])) {
    throw new ImplementationError(
      ImplementationErrorCode.ENCODING_ERROR,
      "keypair/core#keyToMaterial",
      `The ${flag} key material does not have the expected DER prefix!`,
    )
  }

  return new Uint8Array(exportedKey.slice(expectedPrefix.length, expectedPrefix.length + keyLength))
}

/**
 * Calculate the thumbprint of a JWK instance using SHA-256 hash algorithm.
 *
 * @param {JWK} jwk A JSON Web Key instance.
 *
 * @returns {Promise<string>} Resolve to the thumbprint of the JWK instance.
 */
export async function getJwkThumbprint(jwk: JWK): Promise<string> {
  const data = new TextEncoder().encode(JSON.stringify(jwk))
  const hash = await crypto.subtle.digest("SHA-256", data)
  return base64url.encode(new Uint8Array(hash))
}

/**
 * Convert a `CryptoKey` instance into a `JWKEC` key object. The flag determines if the key is private or public. When
 * the key is private, the `d` field is included in the JWK object.
 *
 * @param {CryptoKey} key A `CryptoKey` instance.
 * @param {KeypairOptions.Flag} flag The flag to determine if the key is private or public.
 *
 * @returns {Promise<JWKEC>} Resolve to an object representing a JSON Web Key.
 */
export async function keyToJwk(key: CryptoKey, flag: KeypairOptions.Flag): Promise<JWKEC> {
  const jwk = await crypto.subtle.exportKey("jwk", key)

  return {
    kty: jwk.kty || SUITE_CONSTANT.JWK_TYPE,
    use: jwk.use || SUITE_CONSTANT.JWK_USE,
    key_ops: jwk.key_ops,
    alg: jwk.alg!,
    ext: jwk.ext || true,
    crv: jwk.crv!,
    x: jwk.x!,
    y: jwk.y!,
    d: flag === "private" ? jwk.d! : undefined,
  }
}

/**
 * Convert a `JWKEC` key object into a `CryptoKey` instance. The flag determines if the key is private or public. When
 * the key is private, the `d` field MUST be provided in the `jwk` input.
 *
 * @param {JWKEC} jwk An object representing a JSON Web Key.
 * @param {KeypairOptions.Flag} flag The flag to determine if the key is private or public.
 *
 * @returns {Promise<CryptoKey>} Resolve to a `CryptoKey` instance.
 */
export async function jwkToKey(jwk: JWKEC, flag: KeypairOptions.Flag): Promise<CryptoKey> {
  const keyUsage = jwk.key_ops || (flag === "private" ? ["sign"] : ["verify"])
  const secret = flag === "private" ? jwk.d : undefined

  if (flag === "private" && !secret) {
    throw new ImplementationError(
      ImplementationErrorCode.DECODING_ERROR,
      "keypair/core#jwkToKey",
      "The private key material is missing from the JWK object!",
    )
  }

  const prepare = {
    kty: jwk.kty,
    crv: jwk.crv,
    key_ops: keyUsage,
    ext: jwk.ext || true,
    x: jwk.x,
    y: jwk.y,
    d: secret,
  }

  return await crypto.subtle.importKey(
    "jwk",
    prepare,
    { name: SUITE_CONSTANT.ALGORITHM, namedCurve: jwk.crv },
    true,
    keyUsage as KeyUsage[],
  )
}
