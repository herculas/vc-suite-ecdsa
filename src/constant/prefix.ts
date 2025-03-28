import type { Flag } from "@herculas/vc-data-integrity"

import { Curve } from "./curve.ts"

/**
 * The encoding of an ECDSA P-256 public key MUST start with the two-byte prefix `0x8024` (the varint expression of
 * `0x1200`) followed by the 33-byte compressed public key data.
 *
 * The resulting 35-byte value MUST be encoded using the base-58-btc alphabet, and then prepended with the base-58-btc
 * Multibase header `z`.
 *
 * @see https://www.w3.org/TR/cid/#Multikey
 */
const PUBLIC_KEY_MULTIBASE_256 = "8024"

/**
 * The encoding of an ECDSA P-384 public key MUST start with the two-byte prefix `0x8124` (the varint expression of
 * `0x1201`) followed by the 49-byte compressed public key data.
 *
 * The resulting 51-byte value MUST be encoded using the base-58-btc alphabet, and then prepended with the base-58-btc
 * Multibase header `z`.
 *
 * @see https://www.w3.org/TR/cid/#Multikey
 */
const PUBLIC_KEY_MULTIBASE_384 = "8124"

/**
 * The encoding of an ECDSA P-256 private key MUST start with the two-byte prefix `0x8626` (the varint expression of
 * `0x1306`) followed by the 32-byte private key data.
 *
 * The resulting 34-byte value MUST be encoded using the base-58-btc alphabet, and then prepended with the base-58-btc
 * Multibase header `z`.
 *
 * @see https://www.w3.org/TR/cid/#Multikey
 */
const PRIVATE_KEY_MULTIBASE_256 = "8626"

/**
 * The encoding of an ECDSA P-384 private key MUST start with the two-byte prefix `0x8726` (the varint expression of
 * `0x1307`) followed by the 48-byte private key data.
 *
 * The resulting 50-byte value MUST be encoded using the base-58-btc alphabet, and then prepended with the base-58-btc
 * Multibase header `z`.
 *
 * @see https://www.w3.org/TR/cid/#Multikey
 */
const PRIVATE_KEY_MULTIBASE_384 = "8726"

/**
 * The DER prefix for an ECDSA P-256 public key in SPKI format, which could be decomposed as follows:
 *
 * - `3059`: `SEQUENCE` (89 bytes in total)
 * - `3013`: `SEQUENCE` (19 bytes following)
 * - `0607_2a8648ce3d0201`: `Object Identifier` (7 bytes, 1.2.840.10045.2.1, representing ANSI X9.62 ECDSA algorithm)
 * - `0608_2a8648ce3d030107`: `Object Identifier` (8 bytes, 1.2.840.10045.3.1.7, representing P-256 curve)
 * - `0342`: `BIT STRING` (66 bytes following, 64 bytes for the public key)
 * - `0004`: `Unused bits` (4 bits)
 */
const PUBLIC_KEY_UNCOMPRESSED_256 = "3059301306072a8648ce3d020106082a8648ce3d03010703420004"

/**
 * The DER prefix for an ECDSA P-384 public key in SPKI format, which could be decomposed as follows:
 *
 * - `3076`: `SEQUENCE` (118 bytes in total)
 * - `3010`: `SEQUENCE` (16 bytes following)
 * - `0607_2a8648ce3d0201`: `Object Identifier` (7 bytes, 1.2.840.10045.2.1, representing ANSI X9.62 ECDSA algorithm)
 * - `0605_2b81040022`: `Object Identifier` (5 bytes, 1.3.132.0.34, representing P-384 curve)
 * - `0362`: `BIT STRING` (98 bytes following, 96 bytes for the public key)
 * - `0004`: `Unused bits` (4 bits)
 */
const PUBLIC_KEY_UNCOMPRESSED_384 = "3076301006072a8648ce3d020106052b8104002203620004"

/**
 * The DER prefix for an ECDSA P-256 compressed public key, which could be decomposed as follows:
 *
 * - `3039`: `SEQUENCE` (57 bytes in total)
 * - `3013`: `SEQUENCE` (19 bytes following)
 * - `0607_2a8648ce3d0201`: `Object Identifier` (7 bytes, 1.2.840.10045.2.1, representing ANSI X9.62 ECDSA algorithm)
 * - `0608_2a8648ce3d030107`: `Object Identifier` (8 bytes, 1.2.840.10045.3.1.7, representing P-256 curve)
 * - `0322`: `BIT STRING` (34 bytes following, 32 bytes for the public key)
 * - `00`: `Unused bits` (2 bits)
 */
const PUBLIC_KEY_COMPRESSED_256 = "3039301306072a8648ce3d020106082a8648ce3d030107032200"

/**
 * The DER prefix for an ECDSA P-384 compressed public key, which could be decomposed as follows:
 *
 * - `3046`: `SEQUENCE` (70 bytes in total)
 * - `3010`: `SEQUENCE` (16 bytes following)
 * - `0607_2a8648ce3d0201`: `Object Identifier` (7 bytes, 1.2.840.10045.2.1, representing ANSI X9.62 ECDSA algorithm)
 * - `0605_2b81040022`: `Object Identifier` (5 bytes, 1.3.132.0.34, representing P-384 curve)
 * - `0332`: `BIT STRING` (50 bytes following, 48 bytes for the public key)
 * - `00`: `Unused bits` (2 bits)
 */
const PUBLIC_KEY_COMPRESSED_384 = "3046301006072a8648ce3d020106052b81040022033200"

/**
 * The DER prefix for an ECDSA P-256 private key in PKCS#8 format, which could be decomposed as follows:
 *
 * - `308187`: `SEQUENCE` (135 bytes in total)
 * - `0201_00`: `INTEGER` (1 byte for version, with value 0x0)
 * - `3013`: `SEQUENCE` (19 bytes following)
 * - `0607_2a8648ce3d0201`: `Object Identifier` (7 bytes, 1.2.840.10045.2.1, representing ANSI X9.62 ECDSA algorithm)
 * - `0608_2a8648ce3d030107`: `Object Identifier` (8 bytes, 1.2.840.10045.3.1.7, representing P-256 curve)
 * - `046d`: `OCTET STRING` (109 bytes following)
 * - `306b`: `SEQUENCE` (107 bytes following)
 * - `0201_01`: `INTEGER` (1 byte for version, with value 0x1)
 * - `0420`: `OCTET STRING` (32 bytes following, representing the private key)
 */
const PRIVATE_KEY_UNCOMPRESSED_256 = "308187020100301306072a8648ce3d020106082a8648ce3d030107046d306b0201010420"

/**
 * The DER prefix for an ECDSA P-384 private key in PKCS#8 format, which could be decomposed as follows:
 *
 * - `3081b6`: `SEQUENCE` (182 bytes in total)
 * - `0201_00`: `INTEGER` (1 byte for version, with value 0x0)
 * - `3010`: `SEQUENCE` (16 bytes following)
 * - `0607_2a8648ce3d0201`: `Object Identifier` (7 bytes, 1.2.840.10045.2.1, representing ANSI X9.62 ECDSA algorithm)
 * - `0605_2b81040022`: `Object Identifier` (5 bytes, 1.3.132.0.34, representing P-384 curve)
 * - `04819e`: `OCTET STRING` (158 bytes following)
 * - `30819b`: `SEQUENCE` (155 bytes following)
 * - `0201_01`: `INTEGER` (1 byte for version, with value 0x1)
 * - `0430`: `OCTET STRING` (48 bytes following, representing the private key)
 */
const PRIVATE_KEY_UNCOMPRESSED_384 = "3081b6020100301006072a8648ce3d020106052b8104002204819e30819b0201010430"

/**
 * The DER prefix for an ECDSA P-256 compressed private key, which could be decomposed as follows:
 *
 * - `3067`: `SEQUENCE` (103 bytes in total)
 * - `0201_00`: `INTEGER` (1 byte for version, with value 0x0)
 * - `3013`: `SEQUENCE` (19 bytes following)
 * - `0607_2a8648ce3d0201`: `Object Identifier` (7 bytes, 1.2.840.10045.2.1, representing ANSI X9.62 ECDSA algorithm)
 * - `0608_2a8648ce3d030107`: `Object Identifier` (8 bytes, 1.2.840.10045.3.1.7, representing P-256 curve)
 * - `044d`: `OCTET STRING` (77 bytes following)
 * - `304b`: `SEQUENCE` (75 bytes following)
 * - `0201_01`: `INTEGER` (1 byte for version, with value 0x1)
 * - `0420`: `OCTET STRING` (32 bytes following, representing the private key)
 */
const PRIVATE_KEY_COMPRESSED_256 = "3067020100301306072a8648ce3d020106082a8648ce3d030107044d304b0201010420"

/**
 * The DER prefix for an ECDSA P-384 compressed private key, which could be decomposed as follows:
 *
 * - `308184`: `SEQUENCE` (132 bytes in total)
 * - `0201_00`: `INTEGER` (1 byte for version, with value 0x0)
 * - `3010`: `SEQUENCE` (16 bytes following)
 * - `0607_2a8648ce3d0201`: `Object Identifier` (7 bytes, 1.2.840.10045.2.1, representing ANSI X9.62 ECDSA algorithm)
 * - `0605_2b81040022`: `Object Identifier` (5 bytes, 1.3.132.0.34, representing P-384 curve)
 * - `046d`: `OCTET STRING` (109 bytes following)
 * - `306b`: `SEQUENCE` (107 bytes following)
 * - `0201_01`: `INTEGER` (1 byte for version, with value 0x1)
 * - `0430`: `OCTET STRING` (48 bytes following, representing the private key)
 */
const PRIVATE_KEY_COMPRESSED_384 = "308184020100301006072a8648ce3d020106052b81040022046d306b0201010430"

export const MULTIBASE: Map<Flag, Map<Curve, string>> = new Map([
  [
    "public",
    new Map([
      [Curve.P256, PUBLIC_KEY_MULTIBASE_256],
      [Curve.P384, PUBLIC_KEY_MULTIBASE_384],
    ]),
  ],
  [
    "private",
    new Map([
      [Curve.P256, PRIVATE_KEY_MULTIBASE_256],
      [Curve.P384, PRIVATE_KEY_MULTIBASE_384],
    ]),
  ],
])

export const DER_COMPRESSED: Map<Flag, Map<Curve, string>> = new Map([
  [
    "public",
    new Map([
      [Curve.P256, PUBLIC_KEY_COMPRESSED_256],
      [Curve.P384, PUBLIC_KEY_COMPRESSED_384],
    ]),
  ],
  [
    "private",
    new Map([
      [Curve.P256, PRIVATE_KEY_COMPRESSED_256],
      [Curve.P384, PRIVATE_KEY_COMPRESSED_384],
    ]),
  ],
])

export const DER_UNCOMPRESSED: Map<Flag, Map<Curve, string>> = new Map([
  [
    "public",
    new Map([
      [Curve.P256, PUBLIC_KEY_UNCOMPRESSED_256],
      [Curve.P384, PUBLIC_KEY_UNCOMPRESSED_384],
    ]),
  ],
  [
    "private",
    new Map([
      [Curve.P256, PRIVATE_KEY_UNCOMPRESSED_256],
      [Curve.P384, PRIVATE_KEY_UNCOMPRESSED_384],
    ]),
  ],
])

/**
 * The ECDSA-SD base proof header.
 */
export const CBOR_BASE = "d95d00"

/**
 * The ECDSA-SD derived proof header.
 */
export const CBOR_DERIVED = "d95d01"

/**
 * The prefix of a blank node identifier.
 */
export const BLANK_LABEL = "c14n"
