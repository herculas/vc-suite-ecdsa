import { KeypairOptions } from "@herculas/vc-data-integrity"

import * as PREFIX_CONSTANT from "../constant/prefix.ts"
import * as SUITE_CONSTANT from "../constant/suite.ts"

export type Curve = "P-256" | "P-384"

/**
 * Generate an ECDSA keypair using the Web Crypto API.
 *
 * @param {Curve} curve The curve to use for the keypair.
 *
 * @returns {Promise<CryptoKeyPair>} Resolve to an ECDSA keypair.
 */
export async function generateRawKeypair(curve: Curve): Promise<CryptoKeyPair> {
  return await crypto.subtle.generateKey({ name: SUITE_CONSTANT.ALGORITHM, namedCurve: curve }, true, [
    "sign",
    "verify",
  ])
}

/**
 * Calculate the key material from a CryptoKey instance. The flag determines if the key is private or public.
 *
 * @param {CryptoKey} key A CryptoKey instance.
 * @param {KeypairOptions.Flag} flag The flag to determine if the key is private or public.
 *
 * @returns {Promise<Uint8Array>} Resolve to the key material.
 */
export async function keyToMaterial(key: CryptoKey, flag: KeypairOptions.Flag): Promise<Uint8Array> {
  const keyFormat = flag === "private" ? SUITE_CONSTANT.PRIVATE_KEY_FORMAT : SUITE_CONSTANT.PUBLIC_KEY_FORMAT

  const exportedKey = await crypto.subtle.exportKey(keyFormat, key)
  console.log(exportedKey)

  return new Uint8Array()
}
