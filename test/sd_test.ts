import * as cbor from "cbor2"
import { type Hasher } from "@herculas/vc-data-integrity"

Deno.test("CBOR encode/decode", () => {
  const baseSignature = new Uint8Array(64)
  const publicKey = new Uint8Array(35)
  const hmacKey = new Uint8Array(32)

  const signature_1 = new Uint8Array(64)
  const signature_2 = new Uint8Array(64)
  const signature_3 = new Uint8Array(64)
  const signature_4 = new Uint8Array(64)

  crypto.getRandomValues(baseSignature)
  crypto.getRandomValues(publicKey)
  crypto.getRandomValues(hmacKey)
  crypto.getRandomValues(signature_1)
  crypto.getRandomValues(signature_2)
  crypto.getRandomValues(signature_3)
  crypto.getRandomValues(signature_4)

  const mandatoryPointers = [
    "1",
    "2",
    "3",
    "4",
  ]

  const signatures = [signature_1, signature_2, signature_3, signature_4]
  const encoded_1 = cbor.encode([baseSignature, publicKey, hmacKey, signatures, mandatoryPointers])
  const encoded_2 = cbor.encode({ baseSignature, publicKey, hmacKey, signatures, mandatoryPointers })

  // console.log(format.bytesToHex(encoded_1))
  // console.log(format.bytesToHex(encoded_2))

  const decoded_1 = cbor.decode(encoded_1)
  const decoded_2 = cbor.decode(encoded_2)

  console.log(decoded_1)
  console.log(decoded_2)
})
