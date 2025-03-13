import {
  type Flag,
  format,
  ImplementationError,
  ImplementationErrorCode,
  type JWK,
  type JWKEC,
  multi,
  type VerificationMethodJwk,
  type VerificationMethodMultibase,
} from "@herculas/vc-data-integrity"

import { Curve } from "../constant/curve.ts"
import { ECKeypair } from "./keypair.ts"

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
 * Calculate the thumbprint of a `JWK` instance using SHA-256 hash algorithm.
 *
 * @param {JWK} jwk A JSON Web Key.
 *
 * @returns {Promise<string>} Resolve to the thumbprint of the `JWK` instance.
 */
export async function getJwkThumbprint(jwk: JWK): Promise<string> {
  const data = new TextEncoder().encode(JSON.stringify(jwk))
  const hash = await crypto.subtle.digest("SHA-256", data)
  return multi.base64url.encode(new Uint8Array(hash))
}

/**
 * Export a `CryptoKey` instance to a verification method document. The key is stored in the exported document in either
 * `JWK` or `multibase` format, specified by the `type` field in the document. The `multibase` or `JWK` generated from
 * the above process will ultimately be wrapped into a verification method document, along with other metadata
 * associated with that key, such as the controller, identifier, and expiration date.
 *
 * The flowchart below briefly illustrates this export process:
 *
 *        keyToMaterial                  materialToMultibase                        keypairToMultibase
 *     ┌──────────────────> Key Material ─────────────────────> Multibase Key ──────────────────────────────┐
 *     │                   (octet array)                   (base-58-btc string)                             │
 * CryptoKey                                                                                       Verification Method
 *     │                       keyToJwk                                               keypairToJwk          │
 *     └─────────────────────────────────────────────────────> JSON Web Key ────────────────────────────────┘
 *                                                               (JWKEC)
 */

/**
 * Calculate the uncompressed key material from a `CryptoKey` instance. The flag determines if the key is private or
 * public. It should be noted that this operation will remove the DER prefix from the key material.
 *
 * @param {CryptoKey} key A `CryptoKey` instance.
 * @param {Flag} flag The flag to determine if the key is private or public.
 * @param {Curve} curve The curve to use for the keypair.
 *
 * @returns {Promise<Uint8Array>} Resolve to the uncompressed key material.
 */
export async function keyToMaterial(
  key: CryptoKey,
  flag: Flag,
  curve: Curve,
): Promise<Uint8Array> {
  const realCurve = (key.algorithm as EcKeyAlgorithm).namedCurve as Curve
  if (!realCurve || realCurve !== curve) {
    throw new ImplementationError(
      ImplementationErrorCode.ENCODING_ERROR,
      "keypair/core#keyToMaterial",
      "The key does not have a named curve!",
    )
  }

  const keyFormat = SUITE_CONSTANT.KEY_FORMAT.get(flag)
  const derPrefixHex = PREFIX_CONSTANT.DER_UNCOMPRESSED.get(flag)?.get(curve)
  const materialLength = SUITE_CONSTANT.KEY_UNCOMPRESSED_LENGTH.get(flag)?.get(curve)
  const publicMaterialLength = SUITE_CONSTANT.KEY_UNCOMPRESSED_LENGTH.get("public")?.get(curve)!
  const privateMaterialLength = SUITE_CONSTANT.KEY_UNCOMPRESSED_LENGTH.get("private")?.get(curve)!

  if (!keyFormat || !derPrefixHex || !materialLength || !publicMaterialLength || !privateMaterialLength) {
    throw new ImplementationError(
      ImplementationErrorCode.INVALID_KEYPAIR_CONTENT,
      "keypair/core#keyToMaterial",
      `This suite does not support ${curve} curve ${flag} key!`,
    )
  }

  const derPrefix = format.hexToBytes(derPrefixHex)
  const derMaterialBuffer = await crypto.subtle.exportKey(keyFormat, key)
  const derMaterial = new Uint8Array(derMaterialBuffer)
  const realPrefix = derMaterial.slice(0, derPrefix.length)

  if (!realPrefix.every((byte, index) => byte === derPrefix[index])) {
    throw new ImplementationError(
      ImplementationErrorCode.ENCODING_ERROR,
      "keypair/core#keyToMaterial",
      `The ${flag} key material does not have the expected DER prefix!`,
    )
  }

  const expectedFullLength = derPrefix.length + publicMaterialLength +
    (flag === "private" ? privateMaterialLength + SUITE_CONSTANT.KEY_MATERIAL_FOOTER_LENGTH : 0)
  if (derMaterial.length !== expectedFullLength) {
    throw new ImplementationError(
      ImplementationErrorCode.KEYPAIR_EXPORT_ERROR,
      "keypair/core#keyToMaterial",
      `The ${flag} key material does not have the expected length!`,
    )
  }

  const material = derMaterial.slice(derPrefix.length, derPrefix.length + materialLength)
  return material
}

/**
 * Encode a key material into a multibase string.
 *
 * @param {Uint8Array} material The key material in `Uint8Array` format.
 * @param {Flag} flag The flag to determine if the key is private or public.
 * @param {Curve} curve The curve to use for the keypair.
 *
 * @returns {string} The key material encoded in multibase format.
 */
export function materialToMultibase(
  material: Uint8Array,
  flag: Flag,
  curve: Curve,
): string {
  const multibasePrefixHex = PREFIX_CONSTANT.MULTIBASE.get(flag)?.get(curve)
  const materialLength = SUITE_CONSTANT.KEY_UNCOMPRESSED_LENGTH.get(flag)?.get(curve)

  if (!multibasePrefixHex || !materialLength) {
    throw new ImplementationError(
      ImplementationErrorCode.KEYPAIR_EXPORT_ERROR,
      "keypair/core#materialToMultibase",
      `This suite does not support ${curve} curve ${flag} key!`,
    )
  }

  if (material.length !== materialLength) {
    throw new ImplementationError(
      ImplementationErrorCode.INVALID_KEYPAIR_LENGTH,
      "keypair/core#materialToMultibase",
      `The ${curve} curve ${flag} key material should be a ${materialLength}-octet array!`,
    )
  }

  let compressedMaterial: Uint8Array
  if (flag === "private") {
    compressedMaterial = material
  } else if (flag === "public") {
    const x = material.slice(0, materialLength / 2)
    const y = material.slice(materialLength / 2)
    const even = y[y.length - 1] % 2 === 0
    const prefix = even ? new Uint8Array([0x02]) : new Uint8Array([0x03])
    compressedMaterial = format.concatenate(prefix, x)
  } else {
    throw new ImplementationError(
      ImplementationErrorCode.KEYPAIR_EXPORT_ERROR,
      "keypair/core#materialToMultibase",
      `The key flag ${flag} is not supported!`,
    )
  }

  const multibasePrefix = format.hexToBytes(multibasePrefixHex)
  const multibaseMaterial = format.concatenate(multibasePrefix, compressedMaterial)
  return multi.base58btc.encode(multibaseMaterial)
}

/**
 * Export an ECDSA keypair instance into a verification method containing a keypair in multibase format.
 *
 * @param {ECKeypair} keypair An ECDSA keypair instance.
 * @param {Flag} flag The flag to determine if the key is private or public.
 *
 * @returns {Promise<VerificationMethodMultibase>} Resolve to a verification method containing a multibase key.
 */
export async function keypairToMultibase(
  keypair: ECKeypair,
  flag: Flag,
): Promise<VerificationMethodMultibase> {
  // check the controller and identifier
  if (!keypair.controller || !keypair.id) {
    throw new ImplementationError(
      ImplementationErrorCode.INVALID_KEYPAIR_CONTENT,
      "keypair/core#keypairToMultibase",
      "The keypair should have a controller and an identifier!",
    )
  }

  // prepare the document to be exported
  const document: VerificationMethodMultibase = {
    id: keypair.id!,
    type: SUITE_CONSTANT.KEYPAIR_DOCUMENT_TYPE_MULTI,
    controller: keypair.controller!,
    expires: keypair.expires ? format.toW3CTimestamp(keypair.expires) : undefined,
    revoked: keypair.revoked ? format.toW3CTimestamp(keypair.revoked) : undefined,
  }

  // consider the following 5 cases:
  //
  // 1. The `flag` is `private`, but the private key is missing. Throw an error.
  // 2. The `flag` is `private`, and the public key is missing. Export the private key only.
  // 3. The `flag` is `private`, and the public key is presented. Export the public key and set the `id` accordingly.
  // 4. The `flag` is `public`, but the public key is missing. Throw an error.
  // 5. The `flag` is `public`, and the public key is presented. Export the public key, and set the `id` accordingly.

  if (flag === "private") {
    if (!keypair.privateKey) {
      throw new ImplementationError(
        ImplementationErrorCode.INVALID_KEYPAIR_CONTENT,
        "keypair/core#keypairToMultibase",
        "The private key is missing from the keypair!",
      )
    } else {
      const material = await keyToMaterial(keypair.privateKey, "private", keypair.curve)
      document.secretKeyMultibase = materialToMultibase(material, "private", keypair.curve)
    }
  }

  if (keypair.publicKey) {
    const material = await keyToMaterial(keypair.publicKey, "public", keypair.curve)
    document.publicKeyMultibase = materialToMultibase(material, "public", keypair.curve)
  } else if (flag === "public") {
    throw new ImplementationError(
      ImplementationErrorCode.INVALID_KEYPAIR_CONTENT,
      "keypair/core#keypairToMultibase",
      "The public key is missing from the keypair!",
    )
  }

  return document
}

/**
 * Convert a `CryptoKey` instance into a `JWKEC` key object. The flag determines if the key is private or public. When
 * the key is private, the `d` field is included in the JWK object.
 *
 * @param {CryptoKey} key A `CryptoKey` instance.
 * @param {Flag} flag The flag to determine if the key is private or public.
 *
 * @returns {Promise<JWKEC>} Resolve to an object representing a JSON Web Key.
 */
export async function keyToJwk(key: CryptoKey, flag: Flag): Promise<JWKEC> {
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
 * Export an ECDSA keypair instance into a verification method containing a keypair in `JWK` format.
 *
 * @param {ECKeypair} keypair An ECDSA keypair instance.
 * @param {Flag} flag The flag to determine if the key is private or public.
 *
 * @returns {Promise<VerificationMethodJwk>} Resolve to a verification method containing a JSON Web Key.
 */
export async function keypairToJwk(
  keypair: ECKeypair,
  flag: Flag,
): Promise<VerificationMethodJwk> {
  // check the controller and identifier
  if (!keypair.controller || !keypair.id) {
    throw new ImplementationError(
      ImplementationErrorCode.INVALID_KEYPAIR_CONTENT,
      "keypair/core#keypairToJwk",
      "The keypair should have a controller and an identifier!",
    )
  }

  // prepare the document to be exported
  const document: VerificationMethodJwk = {
    id: keypair.id!,
    type: SUITE_CONSTANT.KEYPAIR_DOCUMENT_TYPE_JWK,
    controller: keypair.controller!,
    expires: keypair.expires ? format.toW3CTimestamp(keypair.expires) : undefined,
    revoked: keypair.revoked ? format.toW3CTimestamp(keypair.revoked) : undefined,
  }

  // consider the following 5 cases:
  //
  // 1. The `flag` is `private`, but the private key is missing. Throw an error.
  // 2. The `flag` is `private`, and the public key is missing. Export the private key only.
  // 3. The `flag` is `private`, and the public key is presented. Export the public key and set the `id` accordingly.
  // 4. The `flag` is `public`, but the public key is missing. Throw an error.
  // 5. The `flag` is `public`, and the public key is presented. Export the public key, and set the `id` accordingly.

  if (flag === "private") {
    if (!keypair.privateKey) {
      throw new ImplementationError(
        ImplementationErrorCode.INVALID_KEYPAIR_CONTENT,
        "keypair/core#keypairToJwk",
        "The private key is missing from the keypair!",
      )
    } else {
      document.secretKeyJwk = await keyToJwk(keypair.privateKey, "private")
    }
  }

  if (keypair.publicKey) {
    document.publicKeyJwk = await keyToJwk(keypair.publicKey, "public")
    document.id = `${keypair.controller}#${await getJwkThumbprint(document.publicKeyJwk)}`
  } else if (flag === "public") {
    throw new ImplementationError(
      ImplementationErrorCode.INVALID_KEYPAIR_CONTENT,
      "keypair/core#keypairToJwk",
      "The public key is missing from the keypair!",
    )
  }

  return document
}

/**
 * Import a verification method document into a `CryptoKey` instance. The key is stored in the verification method
 * document in either JSON Web Key or multibase format, as specified by the type field in the document.
 *
 * The flowchart below briefly illustrates this export process:
 *                                                                                           materialToPublicKey
 *                       multibaseToKeypair                  multibaseToMaterial             materialToPrivateKey
 *  Verification Method ────────────────────> Multibase Key ────────────────────> Key Material ─────────────────┐
 *   (Multibase within)                   (base-58-btc string)                  (octet array)                   │
 *                                                                                                          CryptoKey
 *                         jwkToKeypair                                           jwkToKey                      │
 *  Verification Method ──────────────────> JSON Web Key ───────────────────────────────────────────────────────┘
 *      (JWK within)                          (JWKEC)
 */

/**
 * Import an elliptic curve keypair from a verification method document containing a keypair in multibase format.
 *
 * @param {VerificationMethodMultibase} verificationMethod A verification method fetched from an external source.
 * @param {Curve} curve The curve to use for the keypair.
 * @param {Date} [expires] The expiration date of the keypair.
 * @param {Date} [revoked] The revocation date of the keypair.
 *
 * @returns {Promise<ECKeypair>} Resolve to an elliptic curve keypair instance.
 */
export async function multibaseToKeypair(
  verificationMethod: VerificationMethodMultibase,
  curve: Curve,
  expires?: Date,
  revoked?: Date,
): Promise<ECKeypair> {
  const keypair = new ECKeypair(curve, verificationMethod.id, verificationMethod.controller, expires, revoked)

  // import the private key if it is presented
  if (verificationMethod.secretKeyMultibase) {
    const material = multibaseToMaterial(verificationMethod.secretKeyMultibase, "private", curve)
    keypair.privateKey = await materialToPrivateKey(material, curve)
  }

  // import the public key if it is presented
  if (verificationMethod.publicKeyMultibase) {
    const material = multibaseToMaterial(verificationMethod.publicKeyMultibase, "public", curve)
    keypair.publicKey = await materialToPublicKey(material, curve)
  }

  // both the private and public keys are missing
  if (!verificationMethod.secretKeyMultibase && !verificationMethod.publicKeyMultibase) {
    throw new ImplementationError(
      ImplementationErrorCode.INVALID_KEYPAIR_CONTENT,
      "keypair/core#multibaseToKeypair",
      "Both public and private key materials are missing from the verification method!",
    )
  }

  return keypair
}

/**
 * Decode a multibase encoded private or public key into an `Uint8Array` key material, and check the key material
 * against the multibase prefix according to the specification.
 *
 * @param {string} multibase A multibase encoded private or public key material.
 * @param {Flag} flag The flag to determine if the key is private or public.
 * @param {Curve} curve The curve to use for the keypair.
 *
 * @returns {Uint8Array} The compressed key material in `Uint8Array` format.
 */
export function multibaseToMaterial(
  multibase: string,
  flag: Flag,
  curve: Curve,
): Uint8Array {
  const multibaseMaterial = multi.base58btc.decode(multibase)
  const multibasePrefixHex = PREFIX_CONSTANT.MULTIBASE.get(flag)?.get(curve)
  const materialLength = SUITE_CONSTANT.KEY_COMPRESSED_LENGTH.get(flag)?.get(curve)

  if (!multibasePrefixHex || !materialLength) {
    throw new ImplementationError(
      ImplementationErrorCode.KEYPAIR_IMPORT_ERROR,
      "keypair/core#multibaseToMaterial",
      `This suite does not support ${curve} curve ${flag} key!`,
    )
  }

  const multibasePrefix = format.hexToBytes(multibasePrefixHex)
  if (!multibasePrefix.every((byte, index) => multibaseMaterial[index] === byte)) {
    throw new ImplementationError(
      ImplementationErrorCode.DECODING_ERROR,
      "keypair/core#multibaseToMaterial",
      `The provided ${curve} curve ${flag} key multibase does not match the specified prefix!`,
    )
  }

  const material = multibaseMaterial.slice(multibasePrefix.length)
  if (material.length !== materialLength) {
    throw new ImplementationError(
      ImplementationErrorCode.INVALID_KEYPAIR_LENGTH,
      "keypair/core#multibaseToMaterial",
      `The ${curve} curve ${flag} key material should be a ${materialLength}-octet array!`,
    )
  }

  return material
}

/**
 * Recover an ECDSA private key from the provided key material. Note that this function only works with private key
 * material, and public key material should not be used as input.
 *
 * @param {Uint8Array} material The compressed private key material in `Uint8Array` format.
 * @param {Curve} curve The curve to use for the keypair.
 *
 * @returns {Promise<CryptoKey>} Resolve to the recovered ECDSA private key in `CryptoKey` format.
 */
export async function materialToPrivateKey(
  material: Uint8Array,
  curve: Curve,
): Promise<CryptoKey> {
  const usage: KeyUsage[] = ["sign"]
  const flag: Flag = "private"
  const materialLength = SUITE_CONSTANT.KEY_COMPRESSED_LENGTH.get(flag)?.get(curve)

  if (!materialLength) {
    throw new ImplementationError(
      ImplementationErrorCode.KEYPAIR_IMPORT_ERROR,
      "keypair/core#materialToKey",
      `This suite does not support ${curve} curve ${flag} key!`,
    )
  }

  // construct a JWK using the private key material
  const prepare = {
    kty: SUITE_CONSTANT.JWK_TYPE,
    crv: curve,
    key_ops: usage,
    ext: true,
    x: "",
    y: "",
    d: multi.base64url.encode(material),
  }

  return await crypto.subtle.importKey(
    "jwk",
    prepare,
    { name: SUITE_CONSTANT.ALGORITHM, namedCurve: curve },
    true,
    usage,
  )
}

/**
 * Recover an ECDSA public key from the provided key material. Note that this function only works with public key
 * material, and private key material should not be used as input.
 *
 * @param {Uint8Array} material The compressed public key material in `Uint8Array` format.
 * @param {Curve} curve The curve to use for the keypair.
 *
 * @returns {Promise<CryptoKey>} Resolve to the recovered ECDSA public key in `CryptoKey` format.
 */
export async function materialToPublicKey(
  material: Uint8Array,
  curve: Curve,
): Promise<CryptoKey> {
  const flag: Flag = "public"
  const keyFormat = SUITE_CONSTANT.KEY_FORMAT.get(flag)
  const materialLength = SUITE_CONSTANT.KEY_COMPRESSED_LENGTH.get(flag)?.get(curve)
  const derPrefixHex = PREFIX_CONSTANT.DER_COMPRESSED.get(flag)?.get(curve)

  if (!keyFormat || !materialLength || !derPrefixHex) {
    throw new ImplementationError(
      ImplementationErrorCode.KEYPAIR_IMPORT_ERROR,
      "keypair/core#materialToKey",
      `This suite does not support ${curve} curve ${flag} key!`,
    )
  }

  if (material.length !== materialLength) {
    throw new ImplementationError(
      ImplementationErrorCode.INVALID_KEYPAIR_LENGTH,
      "keypair/core#materialToKey",
      `The ${curve} curve ${flag} key material should be a ${materialLength}-octet array!`,
    )
  }

  const derPrefix = format.hexToBytes(derPrefixHex)
  const derMaterial = format.concatenate(derPrefix, material)
  const usage: KeyUsage[] = ["verify"]

  const firstImport = await crypto.subtle.importKey(
    keyFormat,
    derMaterial,
    { name: SUITE_CONSTANT.ALGORITHM, namedCurve: curve },
    true,
    usage,
  )
  const firstExport = await crypto.subtle.exportKey("jwk", firstImport)
  const secondImport = await crypto.subtle.importKey(
    "jwk",
    firstExport,
    { name: SUITE_CONSTANT.ALGORITHM, namedCurve: curve },
    true,
    usage,
  )
  return secondImport
}

/**
 * Import an elliptic curve keypair from a verification method document containing a keypair in `JWK` format.
 *
 * @param {VerificationMethodJwk} verificationMethod A verification method fetched from an external source.
 * @param {Curve} curve The curve to use for the keypair.
 * @param {Date} expires The expiration date of the keypair.
 * @param {Date} revoked The revocation date of the keypair.
 *
 * @returns {Promise<ECKeypair>} Resolve to an elliptic curve keypair instance.
 */
export async function jwkToKeypair(
  verificationMethod: VerificationMethodJwk,
  curve: Curve,
  expires?: Date,
  revoked?: Date,
): Promise<ECKeypair> {
  const keypair = new ECKeypair(curve, verificationMethod.id, verificationMethod.controller, expires, revoked)

  const innerImport = async (jwk: JWK, flag: Flag, inCurve: Curve) => {
    let convertedJwk: JWKEC
    try {
      convertedJwk = jwk as JWKEC
    } catch (error) {
      throw new ImplementationError(
        ImplementationErrorCode.INVALID_KEYPAIR_CONTENT,
        "keypair/core#jwkToKeypair",
        `The JWK object of ${inCurve} curve ${flag} key is not well-formed: ${error}!`,
      )
    }
    const recoveredKey = await jwkToKey(convertedJwk, flag)
    const recoveredCurve = (recoveredKey.algorithm as EcKeyAlgorithm).namedCurve as Curve

    if (recoveredCurve !== inCurve) {
      throw new ImplementationError(
        ImplementationErrorCode.INVALID_KEYPAIR_CONTENT,
        "keypair/core#jwkToKeypair",
        `The curve ${recoveredCurve} of the recovered key does not match the expected curve ${inCurve}!`,
      )
    }

    return recoveredKey
  }

  // import the private key if it is presented
  if (verificationMethod.secretKeyJwk) {
    keypair.privateKey = await innerImport(verificationMethod.secretKeyJwk, "private", curve)
  }

  // import the public key if it is presented
  if (verificationMethod.publicKeyJwk) {
    keypair.publicKey = await innerImport(verificationMethod.publicKeyJwk, "public", curve)
  }

  // both the private and public keys are missing
  if (!verificationMethod.secretKeyJwk && !verificationMethod.publicKeyJwk) {
    throw new ImplementationError(
      ImplementationErrorCode.INVALID_KEYPAIR_CONTENT,
      "keypair/core#jwkToKeypair",
      "Both public and private key JWKs are missing from the verification method!",
    )
  }

  return keypair
}

/**
 * Convert a `JWKEC` key object into a `CryptoKey` instance. The flag determines if the key is private or public. When
 * the key is private, the `d` field MUST be provided in the `jwk` input.
 *
 * @param {JWKEC} jwk An object representing a JSON Web Key.
 * @param {Flag} flag The flag to determine if the key is private or public.
 *
 * @returns {Promise<CryptoKey>} Resolve to a `CryptoKey` instance.
 */
export async function jwkToKey(jwk: JWKEC, flag: Flag): Promise<CryptoKey> {
  const defaultUsage = flag === "private" ? ["sign"] : ["verify"]
  const keyUsage = (jwk.key_ops || defaultUsage) as KeyUsage[]
  const secret = flag === "private" ? jwk.d : undefined

  if (flag === "private" && !secret) {
    throw new ImplementationError(
      ImplementationErrorCode.DECODING_ERROR,
      "keypair/core#jwkToKey",
      "The private key material is missing from the JWK object!",
    )
  }

  if (jwk.kty !== SUITE_CONSTANT.JWK_TYPE) {
    throw new ImplementationError(
      ImplementationErrorCode.INVALID_KEYPAIR_CONTENT,
      "keypair/core#jwkToKey",
      `The 'kty' field ${jwk.kty} of the JWK object is not supported!`,
    )
  }

  if (!Object.values(Curve).includes(jwk.crv as Curve)) {
    throw new ImplementationError(
      ImplementationErrorCode.INVALID_KEYPAIR_CONTENT,
      "keypair/core#jwkToKey",
      "The 'crv' field is missing from the JWK object!",
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
