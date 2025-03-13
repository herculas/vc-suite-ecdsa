import { type Hasher, ImplementationError, ImplementationErrorCode } from "@herculas/vc-data-integrity"
import { Curve } from "../constant/curve.ts"

/**
 * Construct a hasher based given the elliptic curve.
 *
 * @param {Curve} curve An elliptic curve.
 *
 * @returns {Hasher} A hasher instance.
 */
export function constructHasher(curve: Curve): Hasher {
  if (!Object.values(Curve).includes(curve)) {
    throw new ImplementationError(
      ImplementationErrorCode.ENCODING_ERROR,
      "utils/crypto#constructHasher",
      `Invalid curve: ${curve} is not supported by this implementation.`,
    )
  }

  let algorithm: string
  switch (curve) {
    case Curve.P256:
      algorithm = "SHA-256"
      break
    case Curve.P384:
      algorithm = "SHA-384"
      break
    default:
      throw new ImplementationError(
        ImplementationErrorCode.ENCODING_ERROR,
        "utils/crypto#constructHasher",
        `Invalid curve: ${curve} is not supported by this implementation"`,
      )
  }

  const hasher: Hasher = async (data: Uint8Array): Promise<Uint8Array> => {
    const digest = await crypto.subtle.digest(algorithm, data)
    return new Uint8Array(digest)
  }

  return hasher
}
