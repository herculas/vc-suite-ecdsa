import { assertEquals } from "@std/assert"
import { add } from "../src/mod.ts"
import { Keypair } from "@herculas/vc-data-integrity"

// Deno.test(function addTest() {
//   assertEquals(add(2, 3), 5)
// })

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

  const sig1 = await crypto.subtle.sign({ name: "ECDSA", hash: { name: "SHA-256" } }, re1, new Uint8Array([1, 2, 3, 4, 5, 6]))
  const sig2 = await crypto.subtle.sign({ name: "ECDSA", hash: { name: "SHA-256" } }, rere2, new Uint8Array([1, 2, 3, 4, 5, 6]))

  const sig1Hex = bytesToHex(new Uint8Array(sig1))
  const sig2Hex = bytesToHex(new Uint8Array(sig2))

  console.log(sig1Hex)
  console.log(sig2Hex)
})

