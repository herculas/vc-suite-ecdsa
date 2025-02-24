import {
  document,
  ImplementationError,
  ImplementationErrorCode,
  Keypair,
  type KeypairOptions,
  loader,
  type URI,
  VC_BASE_URL,
  type VerificationMethod,
  type VerificationMethodJwk,
  type VerificationMethodMultibase,
} from "@herculas/vc-data-integrity"

import { Curve } from "../constant/curve.ts"

import * as core from "./core.ts"
import * as SUITE_CONSTANT from "../constant/suite.ts"

/**
 * The elliptic curve keypair class.
 */
export class ECKeypair extends Keypair {
  /**
   * The type of the cryptographic suite used by the keypair instances.
   */
  static override readonly type = SUITE_CONSTANT.ALGORITHM

  /**
   * The specific elliptic curve used in this instance.
   */
  readonly curve: Curve

  /**
   * The elliptic curve public key.
   */
  publicKey?: CryptoKey

  /**
   * The elliptic curve private key.
   */
  privateKey?: CryptoKey

  /**
   * @param {Curve} [_curve] The specific elliptic curve used in this instance.
   * @param {URI} [_id] The identifier of the keypair.
   * @param {URI} [_controller] The controller of the keypair.
   * @param {Date} [_expires] The date and time when the keypair expires.
   * @param {Date} [_revoked] The date and time when the keypair has been revoked.
   */
  constructor(_curve?: Curve, _id?: URI, _controller?: URI, _expires?: Date, _revoked?: Date) {
    super(_id, _controller, _expires, _revoked)
    this.curve = _curve ?? Curve.P256
  }

  /**
   * Initialize an elliptic curve keypair using the Web Crypto API, and set the public and private keys.
   */
  override async initialize() {
    const keypair = await core.generateRawKeypair(this.curve)
    this.publicKey = keypair.publicKey
    this.privateKey = keypair.privateKey

    // set the identifier if the controller is specified
    if (this.controller && !this.id) {
      this.id = `${this.controller}#${await this.generateFingerprint()}`
    }
  }

  /**
   * Calculate the public key fingerprint, multibase + multicodec encoded. The specific fingerprint method is determined
   * by the key suite, and is often either a hash of the public key material, or the full encoded public key. This
   * method is frequently used to initialize the key identifier or generate some types of cryptonym DIDs.
   *
   * @returns {Promise<string>} Resolve to the fingerprint.
   */
  override async generateFingerprint(): Promise<string> {
    if (!this.publicKey) {
      throw new ImplementationError(
        ImplementationErrorCode.INVALID_KEYPAIR_CONTENT,
        "Ed25519Keypair.generateFingerprint",
        "Public key has not been generated!",
      )
    }
    const material = await core.keyToMaterial(this.publicKey, "public", this.curve)
    return core.materialToMultibase(material, "public", this.curve)
  }

  /**
   * Verify that a provided fingerprint matches the public key material belonging to this keypair.
   *
   * @param {string} fingerprint A public key fingerprint.
   *
   * @returns {Promise<boolean>} Resolve to a boolean indicating whether the given fingerprint matches this keypair
   * instance.
   */
  override async verifyFingerprint(fingerprint: string): Promise<boolean> {
    return fingerprint === (await this.generateFingerprint())
  }

  /**
   * Export the serialized representation of the keypair, along with other metadata which can be used to form a proof.
   *
   * @param {KeypairOptions.Export} [options] The options to export the keypair.
   *
   * @returns {Promise<VerificationMethod>} Resolve to a verification method containing the serialized keypair.
   */
  override export(options?: KeypairOptions.Export): Promise<VerificationMethod> {
    // set default options
    options = options ?? {}
    options.flag ||= "public"
    options.type ||= SUITE_CONSTANT.KEYPAIR_DOCUMENT_TYPE_MULTI

    // check if the keypair has been initialized
    if ((options.flag === "private" && !this.privateKey) || (options.flag === "public" && !this.publicKey)) {
      throw new ImplementationError(
        ImplementationErrorCode.KEYPAIR_EXPORT_ERROR,
        "Ed25519Keypair.export",
        `${options.flag} key material has not been generated!`,
      )
    }

    // check if the identifier and controller are well-formed
    if (!this.id || !this.controller || !this.id.startsWith(this.controller)) {
      throw new ImplementationError(
        ImplementationErrorCode.KEYPAIR_EXPORT_ERROR,
        "Ed25519Keypair.export",
        "The identifier or controller of this keypair is not well-formed!",
      )
    }

    // generate the verification method
    if (options.type === SUITE_CONSTANT.KEYPAIR_DOCUMENT_TYPE_MULTI) {
      return core.keypairToMultibase(this, options.flag)
    } else if (options.type === SUITE_CONSTANT.KEYPAIR_DOCUMENT_TYPE_JWK) {
      return core.keypairToJwk(this, options.flag)
    } else {
      throw new ImplementationError(
        ImplementationErrorCode.KEYPAIR_EXPORT_ERROR,
        "Ed25519Keypair.export",
        "The keypair type is not supported!",
      )
    }
  }

  /**
   * Import an elliptic curve keypair from a verification method document.
   *
   * @param {VerificationMethod} inputDocument A verification method document fetched from an external source.
   * @param {ECImportOptions} [options] Options for keypair import.
   *
   * @returns {Promise<ECKeypair>} Resolve to an elliptic curve keypair instance.
   */
  static override async import(
    inputDocument: VerificationMethod,
    options?: ECImportOptions,
  ): Promise<ECKeypair> {
    // set default options
    options = options ?? {}
    options.curve ||= Curve.P256

    // validate the JSON-LD context
    if (options.checkContext) {
      const res = await document.validateContext(inputDocument, VC_BASE_URL.CID_V1, false, loader.basic)
      if (!res.validated) {
        throw new ImplementationError(
          ImplementationErrorCode.INVALID_KEYPAIR_CONTENT,
          "ECKeypair::import",
          "The JSON-LD context is not supported by this application!",
        )
      }
    }

    // check the expiration status
    const expires = inputDocument.expires ? new Date(inputDocument.expires) : undefined
    if (options.checkExpired && expires && expires < new Date()) {
      throw new ImplementationError(
        ImplementationErrorCode.KEYPAIR_EXPIRED_ERROR,
        "Ed25519Keypair::import",
        "The keypair represented by the verification method has expired!",
      )
    }

    // check the revocation status
    const revoked = inputDocument.revoked ? new Date(inputDocument.revoked) : undefined
    if (options.checkRevoked && revoked && revoked < new Date()) {
      throw new ImplementationError(
        ImplementationErrorCode.KEYPAIR_EXPIRED_ERROR,
        "Ed25519Keypair::import",
        "The keypair represented by the verification method has been revoked!",
      )
    }

    // import the keypair from the verification method
    if (inputDocument.type === SUITE_CONSTANT.KEYPAIR_DOCUMENT_TYPE_MULTI) {
      return core.multibaseToKeypair(inputDocument as VerificationMethodMultibase, options.curve, expires, revoked)
    } else if (inputDocument.type === SUITE_CONSTANT.KEYPAIR_DOCUMENT_TYPE_JWK) {
      return core.jwkToKeypair(inputDocument as VerificationMethodJwk, options.curve, expires, revoked)
    } else {
      throw new ImplementationError(
        ImplementationErrorCode.KEYPAIR_IMPORT_ERROR,
        "Ed25519Keypair::import",
        "The keypair type is not supported!",
      )
    }
  }
}

/**
 * The options for importing an elliptic curve keypair, adding the curve parameter.
 */
export interface ECImportOptions extends KeypairOptions.Import {
  curve?: Curve
}
