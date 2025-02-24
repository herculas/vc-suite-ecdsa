import type { KeypairOptions } from "@herculas/vc-data-integrity"

import { Curve } from "./curve.ts"

export const JWK_TYPE = "EC"
export const JWK_USE = "sig"
export const ALGORITHM = "ECDSA"

export const KEYPAIR_DOCUMENT_TYPE_MULTI = "Multikey"
export const KEYPAIR_DOCUMENT_TYPE_JWK = "JsonWebKey"

export const GENERAL_PROOF_TYPE = "DataIntegrityProof"
export const SUITE_RDFC = "ecdsa-rdfc-2019"
export const SUITE_JCS = "ecdsa-jcs-2019"
export const SUITE_SD = "ecdsa-sd-2023"

export const KEY_FORMAT: Map<KeypairOptions.Flag, "pkcs8" | "spki"> = new Map([
  ["public", "spki"],
  ["private", "pkcs8"],
])

export const KEY_UNCOMPRESSED_LENGTH: Map<KeypairOptions.Flag, Map<Curve, number>> = new Map([
  ["public", new Map([[Curve.P256, 64], [Curve.P384, 96]])],
  ["private", new Map([[Curve.P256, 32], [Curve.P384, 48]])],
])

export const KEY_COMPRESSED_LENGTH: Map<KeypairOptions.Flag, Map<Curve, number>> = new Map([
  ["public", new Map([[Curve.P256, 33], [Curve.P384, 49]])],
  ["private", new Map([[Curve.P256, 32], [Curve.P384, 48]])],
])

export const KEY_MATERIAL_FOOTER_LENGTH = 6
