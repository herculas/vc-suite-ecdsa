import {
  type Credential,
  Cryptosuite,
  instance,
  type JsonLdDocument,
  type LoadDocumentCallback,
  multi,
  ProcessingError,
  ProcessingErrorCode,
  type Proof,
  type Verification,
} from "@herculas/vc-data-integrity"

import type { Curve } from "../constant/curve.ts"

import * as core from "./core.ts"
import * as SUITE_CONSTANT from "../constant/suite.ts"

/**
 * The `ecdsa-jcs-2019` cryptographic suite takes an input document, canonicalizes the document using the JSON
 * Canonicalization algorithm, and then cryptographically hashes and signs the output resulting in the production of a
 * data integrity proof.
 *
 * @see https://www.w3.org/TR/vc-di-ecdsa/#ecdsa-jcs-2019
 */
export class EcdsaJcs2019 extends Cryptosuite {
  /**
   * The name of the cryptographic suite.
   *
   * In this suite, this value MUST be `ecdsa-jcs-2019`.
   */
  static override readonly cryptosuite: string = SUITE_CONSTANT.SUITE_JCS

  /**
   * Create a data integrity proof given an unsecured data document.
   *
   * @param {JsonLdDocument} unsecuredDocument An unsecured data document to create a proof for.
   * @param {object} options A set of options to use when creating the proof.
   *
   * @returns {Promise<Proof>} Resolve to a data integrity proof.
   *
   * @see https://www.w3.org/TR/vc-di-ecdsa/#create-proof-ecdsa-jcs-2019
   */
  static override async createProof(
    unsecuredDocument: JsonLdDocument,
    options: {
      curve: Curve
      proof: Proof
      documentLoader: LoadDocumentCallback
    },
  ): Promise<Proof> {
    // Procedure:
    //
    // 1. Let `proof` be a clone of `options`.
    // 2. If `unsecuredDocument.@context` is present, set `proof.@context` to `unsecuredDocument.@context`.
    // 3. Let `proofConfig` be the result of running the proof configuration algorithm with `proof` passed as the
    //    `options` parameter.
    // 4. Let `transformedData` be the result of running the transformation algorithm with `unsecuredDocument` and
    //    `options` passed as parameters.
    // 5. Let `hashData` be the result of running the hashing algorithm with `transformedData` and `proofConfig` passed
    //    as parameters.
    // 6. Let `proofBytes` be the result of running the proof serialization algorithm with `hashData` and `options`
    //    passed as parameters.
    // 7. Let `proof.proofValue` be a base58-btc-encoded multibase value of `proofBytes`.
    // 8. Return `proof` as the data integrity proof.

    const cloneProof = structuredClone(options.proof)

    const unsecuredCredential = unsecuredDocument as Credential
    if (unsecuredCredential["@context"]) {
      cloneProof["@context"] = unsecuredCredential["@context"]
    }

    const canonicalProofConfig = core.configJcs({ proof: cloneProof })
    const canonicalDocument = core.transformJcs(unsecuredCredential, options)
    const hashData = await core.hashRdfcJcs(canonicalDocument, canonicalProofConfig, { curve: options.curve })
    const proofBytes = await core.serializeRdfcJcs(hashData, options)

    cloneProof.proofValue = multi.base58btc.encode(proofBytes)
    return cloneProof
  }

  /**
   * Verify a data integrity proof given a secured data document.
   *
   * @param {JsonLdDocument} securedDocument A secured data document to verify a proof for.
   * @param {object} options A set of options to use when verifying the proof.
   *
   * @returns {Promise<Result.Verification>} Resolve to a verification result.
   *
   * @see https://www.w3.org/TR/vc-di-ecdsa/#verify-proof-ecdsa-jcs-2019
   */
  static override async verifyProof(
    securedDocument: JsonLdDocument,
    options: {
      curve: Curve
      documentLoader: LoadDocumentCallback
    },
  ): Promise<Verification> {
    // Procedure:
    //
    // 1. Let `unsecuredDocument` be a copy of `securedDocument` with the `proof` property removed.
    // 2. Let `proofOptions` be the result of a copy of `securedDocument.proof` with the `proofValue` property removed.
    // 3. Let `proofBytes` be the multibase decoded base58-btc value in `securedDocument.proof.proofValue`.
    // 4. If `proofOptions.@context` exists:
    //
    //    4.1. Check that the `securedDocument.@context` starts with all values contained in the `proofOptions.@context`
    //         in the same order. Otherwise, set `verified` to `false` and skip to the last step.
    //    4.2. Set `unsecuredDocument.@context` equal to `proofOptions.@context`.
    //
    // 5. Let `transformedData` be the result of running the transformation algorithm with `unsecuredDocument` and
    //    `proofOptions` passed as parameters.
    // 6. Let `proofConfig` be the result of running the proof configuration algorithm with `proofOptions` passed as
    //    parameters.
    // 7. Let `hashData` be the result of running the hashing algorithm with `transformedData` and `proofConfig` passed
    //    as parameters.
    // 8. Let `verified` be the result of running the proof verification algorithm with `hashData`, `proofBytes`, and
    //    `proofConfig` passed as parameters.
    // 9. Return a verification result with `verified` and `verifiedDocument` set to `unsecuredDocument` if `verified`
    //    is `true`.

    const securedCredential = securedDocument as Credential

    const unsecuredCredential = structuredClone(securedCredential)
    delete unsecuredCredential.proof

    const proofOptions = structuredClone(securedCredential.proof) as Proof
    delete proofOptions.proofValue

    const proofBytes = multi.base58btc.decode((securedCredential.proof as Proof).proofValue!)

    if (proofOptions["@context"]) {
      let proofContext = proofOptions["@context"]
      let securedContext = securedCredential["@context"]

      if (!securedContext) {
        return {
          verified: false,
          errors: [
            new ProcessingError(
              ProcessingErrorCode.PROOF_VERIFICATION_ERROR,
              "EcdsaJcs2019::verifyProof",
              "The secured document does not contain a context.",
            ),
          ],
        }
      }

      // change to array
      proofContext = Array.isArray(proofContext) ? proofContext : [proofContext]
      securedContext = Array.isArray(securedContext) ? securedContext : [securedContext]

      // check that the `securedDocument.@context` starts with all values contained in the `proofOptions.@context`
      // in the same order
      if (
        securedContext.length < proofContext.length ||
        proofContext.some((ctx, index) => !instance.deepEqual(ctx, securedContext[index]))
      ) {
        return {
          verified: false,
          errors: [
            new ProcessingError(
              ProcessingErrorCode.PROOF_VERIFICATION_ERROR,
              "EcdsaJcs2019::verifyProof",
              "The secured document context does not match the proof context.",
            ),
          ],
        }
      }

      unsecuredCredential["@context"] = proofContext
    }

    const transformOptions = { curve: options.curve, proof: proofOptions, documentLoader: options.documentLoader }
    const canonicalDocument = core.transformJcs(unsecuredCredential, transformOptions)
    const canonicalProofConfig = core.configJcs(transformOptions)
    const hashData = await core.hashRdfcJcs(canonicalDocument, canonicalProofConfig, { curve: options.curve })
    const verified = await core.verifyRdfcJcs(hashData, proofBytes, transformOptions)

    return {
      verified,
      verifiedDocument: verified ? unsecuredCredential : undefined,
    }
  }
}
