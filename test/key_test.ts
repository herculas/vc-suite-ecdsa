import { assert, assertEquals, assertExists } from "@std/assert"
import type { CIDDocument } from "@herculas/vc-data-integrity"

import { Curve } from "../src/constant/curve.ts"
import { ECKeypair } from "../src/key/keypair.ts"
import { generateRawKeypair, jwkToKey, keyToJwk } from "../src/key/core.ts"

import * as CID_DOCUMENT_1 from "./mock/cid-1.json" with { type: "json" }
import * as CID_DOCUMENT_2 from "./mock/cid-2.json" with { type: "json" }

Deno.test("Fingerprint generation and verification (P-256)", async () => {
  const keypair = new ECKeypair(Curve.P256)
  await keypair.initialize()

  const fingerprint = await keypair.generateFingerprint()
  const result = await keypair.verifyFingerprint(fingerprint)

  assert(result)
})

Deno.test("Fingerprint generation and verification (P-384)", async () => {
  const keypair = new ECKeypair(Curve.P384)
  await keypair.initialize()

  const fingerprint = await keypair.generateFingerprint()
  const result = await keypair.verifyFingerprint(fingerprint)

  assert(result)
})

Deno.test("Keypair import and export: raw functions (P-256)", async () => {
  const keypair = await generateRawKeypair(Curve.P256)

  const jwkPrivate = await keyToJwk(keypair.privateKey, "private")
  const jwkPublic = await keyToJwk(keypair.publicKey, "public")

  const recoveredPrivate = await jwkToKey(jwkPrivate, "private")
  const recoveredPublic = await jwkToKey(jwkPublic, "public")

  const jwkPrivate2 = await keyToJwk(recoveredPrivate, "private")
  const jwkPublic2 = await keyToJwk(recoveredPublic, "public")

  assertEquals(jwkPrivate, jwkPrivate2)
  assertEquals(jwkPublic, jwkPublic2)
})

Deno.test("Keypair import and export: raw functions (P-384)", async () => {
  const keypair = await generateRawKeypair(Curve.P384)

  const jwkPrivate = await keyToJwk(keypair.privateKey, "private")
  const jwkPublic = await keyToJwk(keypair.publicKey, "public")

  const recoveredPrivate = await jwkToKey(jwkPrivate, "private")
  const recoveredPublic = await jwkToKey(jwkPublic, "public")

  const jwkPrivate2 = await keyToJwk(recoveredPrivate, "private")
  const jwkPublic2 = await keyToJwk(recoveredPublic, "public")

  assertEquals(jwkPrivate, jwkPrivate2)
  assertEquals(jwkPublic, jwkPublic2)
})

Deno.test("Keypair export: encapsulated (P-256)", async () => {
  const curve = Curve.P256
  const keypair = new ECKeypair(curve)
  keypair.controller = "did:example:1145141919810"
  await keypair.initialize()

  const jwkPrivate = await keypair.export({ type: "JsonWebKey", flag: "private" })
  const jwkPublic = await keypair.export({ type: "JsonWebKey", flag: "public" })

  const multibasePrivate = await keypair.export({ type: "Multikey", flag: "private" })
  const multibasePublic = await keypair.export({ type: "Multikey", flag: "public" })

  assertExists(jwkPrivate)
  assertExists(jwkPublic)
  assertExists(multibasePrivate)
  assertExists(multibasePublic)
})

Deno.test("Keypair export: encapsulated (P-384)", async () => {
  const curve = Curve.P384
  const keypair = new ECKeypair(curve)
  keypair.controller = "did:example:1145141919810"
  await keypair.initialize()

  const jwkPrivate = await keypair.export({ type: "JsonWebKey", flag: "private" })
  const jwkPublic = await keypair.export({ type: "JsonWebKey", flag: "public" })

  const multibasePrivate = await keypair.export({ type: "Multikey", flag: "private" })
  const multibasePublic = await keypair.export({ type: "Multikey", flag: "public" })

  assertExists(jwkPrivate)
  assertExists(jwkPublic)
  assertExists(multibasePrivate)
  assertExists(multibasePublic)
})

Deno.test("Keypair export and import: JSON Web Key (P-256)", async () => {
  const curve = Curve.P256
  const keypair = new ECKeypair(curve)
  keypair.controller = "did:example:1145141919810"
  await keypair.initialize()

  const jwkPrivate = await keypair.export({ type: "JsonWebKey", flag: "private" })
  const jwkPublic = await keypair.export({ type: "JsonWebKey", flag: "public" })

  const recoveredPublicOnly = await ECKeypair.import(jwkPublic, { curve })
  const recoveredBoth = await ECKeypair.import(jwkPrivate, { curve })

  assertExists(recoveredPublicOnly.publicKey)
  assertExists(recoveredBoth.privateKey)
  assertExists(recoveredBoth.publicKey)
})

Deno.test("Keypair export and import: JSON Web Key (P-384)", async () => {
  const curve = Curve.P384
  const keypair = new ECKeypair(curve)
  keypair.controller = "did:example:1145141919810"
  await keypair.initialize()

  const jwkPrivate = await keypair.export({ type: "JsonWebKey", flag: "private" })
  const jwkPublic = await keypair.export({ type: "JsonWebKey", flag: "public" })

  const recoveredPublicOnly = await ECKeypair.import(jwkPublic, { curve })
  const recoveredBoth = await ECKeypair.import(jwkPrivate, { curve })

  assertExists(recoveredPublicOnly.publicKey)
  assertExists(recoveredBoth.privateKey)
  assertExists(recoveredBoth.publicKey)
})

Deno.test("Keypair export and import: Multibase (P-256)", async () => {
  const curve = Curve.P256
  const keypair = new ECKeypair(curve)
  keypair.controller = "did:example:1145141919810"
  await keypair.initialize()

  const multibasePrivate = await keypair.export({ type: "Multikey", flag: "private" })
  const multibasePublic = await keypair.export({ type: "Multikey", flag: "public" })

  const recoveredPublicOnly = await ECKeypair.import(multibasePublic, { curve })
  const recoveredBoth = await ECKeypair.import(multibasePrivate, { curve })

  assertExists(recoveredPublicOnly.publicKey)
  assertExists(recoveredBoth.privateKey)
  assertExists(recoveredBoth.publicKey)
})

Deno.test("Keypair export and import: Multibase (P-384)", async () => {
  const curve = Curve.P384
  const keypair = new ECKeypair(curve)
  keypair.controller = "did:example:1145141919810"
  await keypair.initialize()

  const multibasePrivate = await keypair.export({ type: "Multikey", flag: "private" })
  const multibasePublic = await keypair.export({ type: "Multikey", flag: "public" })

  const recoveredPublicOnly = await ECKeypair.import(multibasePublic, { curve })
  const recoveredBoth = await ECKeypair.import(multibasePrivate, { curve })

  assertExists(recoveredPublicOnly.publicKey)
  assertExists(recoveredBoth.privateKey)
  assertExists(recoveredBoth.publicKey)
})

Deno.test("Keypair import and verification (P-256)", async () => {
  const curve = Curve.P256
  const cid = CID_DOCUMENT_1.default as CIDDocument
  const method = cid.verificationMethod![0]
  const recoveredKey = await ECKeypair.import(method, { curve })

  const data = crypto.getRandomValues(new Uint8Array(12))
  const signature = await crypto.subtle.sign(
    { name: "ECDSA", hash: { name: "SHA-256" } },
    recoveredKey.privateKey!,
    data,
  )
  const result = await crypto.subtle.verify(
    { name: "ECDSA", hash: { name: "SHA-256" } },
    recoveredKey.publicKey!,
    signature,
    data,
  )
  assert(result)
})

Deno.test("Keypair import and verification (P-384)", async () => {
  const curve = Curve.P384
  const cid = CID_DOCUMENT_2.default as CIDDocument
  const method = cid.verificationMethod![0]
  const recoveredKey = await ECKeypair.import(method, { curve })

  const data = crypto.getRandomValues(new Uint8Array(12))
  const signature = await crypto.subtle.sign(
    { name: "ECDSA", hash: { name: "SHA-384" } },
    recoveredKey.privateKey!,
    data,
  )
  const result = await crypto.subtle.verify(
    { name: "ECDSA", hash: { name: "SHA-384" } },
    recoveredKey.publicKey!,
    signature,
    data,
  )
  assert(result)
})
