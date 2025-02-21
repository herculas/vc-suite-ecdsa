import { base64url, format } from "@herculas/vc-data-integrity"
import { generateRawKeypair, jwkToKey, keyToJwk, keyToMaterial } from "../src/key/core.ts"
import { Curve } from "../src/constant/curve.ts"

Deno.test("generate raw keypair", async () => {
  const pair = await generateRawKeypair(Curve.P384)
  console.log(pair)
})

Deno.test("test key to material", async () => {
  const keypair = await generateRawKeypair(Curve.P256)
  const privateMaterial = await keyToMaterial(keypair.privateKey, "private")
  const publicMaterial = await keyToMaterial(keypair.publicKey, "public")

  console.log(format.bytesToHex(privateMaterial))
  console.log(format.bytesToHex(publicMaterial))
})

Deno.test("calculate u8", async () => {
  const keypair = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"])
  const secretKey = await crypto.subtle.exportKey("pkcs8", keypair.privateKey)
  const publicKey = await crypto.subtle.exportKey("spki", keypair.publicKey)

  // const rawSecretKey = await crypto.subtle.exportKey("raw", keypair.privateKey)
  const rawPublicKey = await crypto.subtle.exportKey("raw", keypair.publicKey)

  console.log(format.bytesToHex(new Uint8Array(rawPublicKey)))

  // console.log(format.bytesToHex(new Uint8Array(secretKey)))
  console.log(format.bytesToHex(new Uint8Array(publicKey)))

  // const keypair = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-384" }, true, ["sign", "verify"])
  // const exportedKey = await crypto.subtle.exportKey("spki", keypair.publicKey)

  // console.log(format.bytesToHex(new Uint8Array(exportedKey)))
})

Deno.test("test jwk export", async () => {
  const keypair = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"])

  const secretJwk = await keyToJwk(keypair.privateKey, "private")
  const publicJwk = await keyToJwk(keypair.publicKey, "public")

  const secretMulti = await crypto.subtle.exportKey("pkcs8", keypair.privateKey)
  const publicMulti = await crypto.subtle.exportKey("spki", keypair.publicKey)

  const secretMultiHex = format.bytesToHex(new Uint8Array(secretMulti))
  const publicMultiHex = format.bytesToHex(new Uint8Array(publicMulti))

  // console.log(secretJwk)
  // console.log(publicJwk)
  // console.log(publicJwk)

  const decodedSecret = base64url.decode(secretJwk.d!) // equal to secret multi hex sliced from 72 to 136
  const decodedPublicX = base64url.decode(publicJwk.x!)
  const decodedPublicY = base64url.decode(publicJwk.y!)

  console.log("------- secret multi hex -------")
  console.log("from jwk: ", format.bytesToHex(decodedSecret))
  console.log("from mul: ", secretMultiHex.slice(72, 72 + 64))

  console.log("------- public multi hex -------")
  console.log("from jwk x: ", format.bytesToHex(decodedPublicX))
  console.log("from jwk y: ", format.bytesToHex(decodedPublicY))
  console.log("from mul  : ", publicMultiHex.slice(54))

  // secretJwk.x = ""
  // secretJwk.y = ""

  // const importedJwkSecret = await jwkToKey(secretJwk, "private")
  // const importedJwkPublic = await jwkToKey(publicJwk, "public")

  // // console.log(importedJwkSecret)
  // // console.log(importedJwkPublic)

  // const reSecretJwk = await keyToJwk(importedJwkSecret, "private")
  // const rePublicJwk = await keyToJwk(importedJwkPublic, "public")

  // console.log(rePublicJwk)
})

Deno.test("cal a", () => {
  const u8 = new Uint8Array([
    48,
    70,
    48,
    16,
    6,
    7,
    42,
    134,
    72,
    206,
    61,
    2,
    1,
    6,
    5,
    43,
    129,
    4,
    0,
    34,
    3,
    50,
    0,
  ])

  console.log(format.bytesToHex(u8))
})

Deno.test("aa", async () => {
  // const keypair = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"])
  // const exportedKey = await crypto.subtle.exportKey("pkcs8", keypair.privateKey)

  // // convert exportedKey to a hex string
  // const hex = Array.from(new Uint8Array(exportedKey)).map((byte) => byte.toString(16).padStart(2, "0")).join("")
  // console.log(hex)

  // const exportedKeyArray = new Uint8Array(exportedKey)
  // const trunckedExportedKeyArray = exportedKeyArray.slice(0, 68)

  const keyFull = new Uint8Array([
    0x30,
    0x81,
    0x87,
    0x02,
    0x01,
    0x00,
    0x30,
    0x13,
    0x06,
    0x07,
    0x2a,
    0x86,
    0x48,
    0xce,
    0x3d,
    0x02,
    0x01,
    0x06,
    0x08,
    0x2a,
    0x86,
    0x48,
    0xce,
    0x3d,
    0x03,
    0x01,
    0x07,
    0x04,
    0x6d,
    0x30,
    0x6b,
    0x02,
    0x01,
    0x01,
    0x04,
    0x20,
    0xc3,
    0x30,
    0x26,
    0x00,
    0x02,
    0xd3,
    0x00,
    0xb5,
    0x38,
    0x3f,
    0x5f,
    0x16,
    0xbe,
    0x01,
    0xea,
    0xec,
    0x4c,
    0x03,
    0x0b,
    0xd4,
    0x41,
    0xe1,
    0x77,
    0xca,
    0x14,
    0x1a,
    0xf7,
    0x8f,
    0xbb,
    0xf2,
    0x24,
    0x93,
    0xa1,
    0x44,
    0x03,
    0x42,
    0x00,
    0x04,
    0xdc,
    0x35,
    0x31,
    0xc4,
    0xe4,
    0xbc,
    0x3e,
    0x3a,
    0x8d,
    0x9e,
    0x4b,
    0x8e,
    0x93,
    0xdf,
    0x40,
    0xfd,
    0xa9,
    0x25,
    0x02,
    0x10,
    0xad,
    0xcf,
    0x06,
    0xa5,
    0xeb,
    0x89,
    0x28,
    0x43,
    0x49,
    0x4f,
    0xff,
    0xb7,
    0x6f,
    0xe0,
    0x83,
    0xbb,
    0xb4,
    0xd5,
    0x73,
    0x36,
    0x81,
    0x7b,
    0x4d,
    0xa6,
    0xed,
    0xf5,
    0x10,
    0xeb,
    0x78,
    0xcf,
    0x16,
    0x0c,
    0xb2,
    0x4d,
    0xc4,
    0x6b,
    0xbe,
    0xcb,
    0xe0,
    0x26,
    0x68,
    0xaa,
    0xfa,
    0xac,
  ])

  const keyPartial = new Uint8Array([
    0x30,
    0x41,
    0x02,
    0x01,
    0x00,
    0x30,
    0x13,
    0x06,
    0x07,
    0x2a,
    0x86,
    0x48,
    0xce,
    0x3d,
    0x02,
    0x01,
    0x06,
    0x08,
    0x2a,
    0x86,
    0x48,
    0xce,
    0x3d,
    0x03,
    0x01,
    0x07,
    0x04,
    0x27,
    0x30,
    0x25,
    0x02,
    0x01,
    0x01,
    0x04,
    0x20,
    0xc3,
    0x30,
    0x26,
    0x00,
    0x02,
    0xd3,
    0x00,
    0xb5,
    0x38,
    0x3f,
    0x5f,
    0x16,
    0xbe,
    0x01,
    0xea,
    0xec,
    0x4c,
    0x03,
    0x0b,
    0xd4,
    0x41,
    0xe1,
    0x77,
    0xca,
    0x14,
    0x1a,
    0xf7,
    0x8f,
    0xbb,
    0xf2,
    0x24,
    0x93,
  ])

  const re1 = await crypto.subtle.importKey("pkcs8", keyFull, { name: "ECDSA", namedCurve: "P-256" }, true, ["sign"])
  const re2 = await crypto.subtle.importKey("pkcs8", keyPartial, { name: "ECDSA", namedCurve: "P-256" }, true, ["sign"])

  const reJwk1 = await crypto.subtle.exportKey("jwk", re1)
  const reJwk2 = await crypto.subtle.exportKey("jwk", re2)

  // console.log(reJwk1)
  // console.log(reJwk2)

  const reMat1 = await crypto.subtle.exportKey("pkcs8", re1)
  const reMat2 = await crypto.subtle.exportKey("pkcs8", re2)

  const bytesToHex = (bytes: Uint8Array) => {
    return Array.from(bytes).map((byte) => byte.toString(16).padStart(2, "0")).join("")
  }

  const rere2 = await crypto.subtle.importKey("jwk", reJwk2, { name: "ECDSA", namedCurve: "P-256" }, true, ["sign"])
  const rereMat2 = await crypto.subtle.exportKey("pkcs8", rere2)

  const sig1 = await crypto.subtle.sign(
    { name: "ECDSA", hash: { name: "SHA-256" } },
    re1,
    new Uint8Array([1, 2, 3, 4, 5, 6]),
  )
  const sig2 = await crypto.subtle.sign(
    { name: "ECDSA", hash: { name: "SHA-256" } },
    rere2,
    new Uint8Array([1, 2, 3, 4, 5, 6]),
  )

  const sig1Hex = bytesToHex(new Uint8Array(sig1))
  const sig2Hex = bytesToHex(new Uint8Array(sig2))

  console.log(sig1Hex)
  console.log(sig2Hex)
})
