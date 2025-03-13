import {
  type Credential,
  Cryptosuite,
  type JsonLdDocument,
  type LoadDocumentCallback,
  type Proof,
  type URNScheme,
  type Verification,
} from "@herculas/vc-data-integrity"

import type { Curve } from "../constant/curve.ts"

import * as core from "./core.ts"
import * as SUITE_CONSTANT from "../constant/suite.ts"

/**
 * The `ecdsa-sd-2023` cryptographic suite takes an input document, canonicalizes the document using the RDF Dataset
 * Canonicalization algorithm, and then cryptographically hashes and signs the output resulting in the production of a
 * data integrity proof.
 *
 * @see https://www.w3.org/TR/vc-di-ecdsa/#ecdsa-sd-2023
 */
export class EcdsaSd2023 extends Cryptosuite {
  /**
   * The name of the cryptographic suite.
   *
   * In this suite, this value MUST be `ecdsa-sd-2023`.
   */
  static override readonly cryptosuite: string = SUITE_CONSTANT.SUITE_SD

  /**
   * Create a base data integrity proof given an unsecured data document.
   *
   * @param {JsonLdDocument} unsecuredDocument An unsecured data document to create a proof for.
   * @param {object} options A set of options to use when creating the proof.
   *
   * @returns {Promise<Proof>} Resolve to a base data integrity proof.
   */
  static override async createProof(
    unsecuredDocument: JsonLdDocument,
    options: {
      curve: Curve
      proof: Proof
      mandatoryPointers: Array<string>
      documentLoader: LoadDocumentCallback
      urnScheme?: URNScheme
      randomString?: string
    },
  ): Promise<Proof> {
    // Procedure:
    //
    // 1. Let `proof` be a clone of the proof options, `options`.
    // 2. Let `proofConfig` be the result of running the Base Proof Configuration algorithm with `options` passed as a
    //    parameter.
    // 3. Let `transformedData` be the result of running the Base Proof Transformation algorithm with
    //    `unsecuredDocument`, `proofConfig`, and `options` passed as parameters.
    // 4. Let `hashData` be the result of running the Base Proof Hashing algorithm with `transformedData` and
    //    `proofConfig` passed as a parameters.
    // 5. Let `proofBytes` be the result of running the Base Proof Serialization algorithm with `hashData` and `options`
    //    passed as parameters.
    // 6. Let `proof.proofValue` be a base64-url-encoded Multibase value of the `proofBytes`.
    // 7. Return `proof` as the data integrity proof.

    const proof = structuredClone(options.proof)
    const proofConfig = await core.configSd(unsecuredDocument as Credential, options)
    const transformedData = await core.transformSd(unsecuredDocument as Credential, options)
    const hashData = await core.hashSd(transformedData, proofConfig, options)
    const proofValue = await core.serializeSd(hashData, options)
    proof.proofValue = proofValue
    return proof
  }

  /**
   * Create a selective disclosure derived proof. This method will be called by a holder of an ecdsa-sd-2023-protected
   * verifiable credential. The derived proof is to be given to the verifier.
   *
   * @param {JsonLdDocument} securedDocument A secured data document with a base proof in it.
   * @param {object} options A set of options to use when deriving the proof.
   *
   * @returns {Promise<Proof>} Resolve to a selective disclosure proof.
   *
   * @see https://www.w3.org/TR/vc-di-ecdsa/#add-derived-proof-ecdsa-sd-2023
   */
  static override async deriveProof(
    securedDocument: JsonLdDocument,
    options: {
      curve: Curve
      documentLoader: LoadDocumentCallback
      selectivePointers: Array<string>
      urnScheme?: URNScheme
      randomString?: string
    },
  ): Promise<Proof> {
    // Procedure:
    //
    // 2. Initialize `newProof` to a shallow copy of `proof`.
    // 3. Replace `proofValue` in `newProof` with the result of calling the `serializeDerivedProofValue` function,
    //    passing `baseSignature`, `publicKey`, `signatures`, `labelMap`, and `mandatoryIndexes`.
    // 4. Set the value of the "proof" property in `revealDocument` to `newProof`.

    const securedCredential = securedDocument as Credential

    const unsecuredCredential = structuredClone(securedCredential)
    delete unsecuredCredential.proof

    const newProof = structuredClone(securedCredential.proof) as Proof
    const proofValue = await core.deriveSd(unsecuredCredential, newProof, options)

    newProof.proofValue = proofValue
    return newProof
  }

  /**
   * Verify a selective disclosure proof given a secured data document with a derived proof in it.
   *
   * @param {JsonLdDocument} securedDocument A secured data document with a derived proof in it.
   * @param {object} options A set of options to use when verifying the proof.
   *
   * @returns {Promise<Verification>} Resolve to a verification result.
   *
   * @see https://www.w3.org/TR/vc-di-ecdsa/#verify-derived-proof-ecdsa-sd-2023
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
    // 1. Let `unsecuredDocument` be a copy of document with the `proof` value removed.
    // 9. Return a verification result with `verified` and `verifiedDocument` set to `unsecuredDocument` if `verified`
    //    is true.

    const securedCredential = securedDocument as Credential

    const unsecuredCredential = structuredClone(securedCredential)
    delete unsecuredCredential.proof

    const proof = structuredClone(securedCredential.proof) as Proof
    const verified = await core.verifySd(unsecuredCredential, proof, options)

    return {
      verified,
      verifiedDocument: verified ? unsecuredCredential : undefined,
    }
  }
}
