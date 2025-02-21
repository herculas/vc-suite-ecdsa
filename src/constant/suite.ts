import type { KeypairOptions } from "@herculas/vc-data-integrity"

import { Curve } from "./curve.ts"

export const JWK_TYPE = "EC"
export const JWK_USE = "sig"
export const ALGORITHM = "ECDSA"

export const KEYPAIR_DOCUMENT_TYPE_MULTI = "Multikey"
export const KEYPAIR_DOCUMENT_TYPE_JWK = "JsonWebKey"

export const GENERAL_PROOF_TYPE = "DataIntegrityProof"

export const KEY_FORMAT: Map<KeypairOptions.Flag, "pkcs8" | "spki"> = new Map([
  ["public", "spki"],
  ["private", "pkcs8"],
])

export const KEY_MATERIAL_LENGTH: Map<KeypairOptions.Flag, Map<Curve, number>> = new Map([
  ["public", new Map([[Curve.P256, 64], [Curve.P384, 96]])],
  ["private", new Map([[Curve.P256, 32], [Curve.P384, 48]])],
])
