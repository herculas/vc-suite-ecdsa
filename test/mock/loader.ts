import { type JsonLdDocument, loader } from "@herculas/vc-data-integrity"

import * as CID_FILE_1 from "./cid-1.json" with { type: "json" }
import * as CID_FILE_2 from "./cid-2.json" with { type: "json" }

export const testLoader = loader.extend((url) => {
  const document = new Map<string, JsonLdDocument>([
    ["did:key:zDnaepBuvsQ8cpsWrVKw8fbpGpvPeNSjVPTWoq6cRqaYzBKVP", CID_FILE_1.default],
    ["did:key:z82LkuBieyGShVBhvtE2zoiD6Kma4tJGFtkAhxR5pfkp5QPw4LutoYWhvQCnGjdVn14kujQ", CID_FILE_2.default],
  ])

  if (document.has(url)) {
    return Promise.resolve({
      documentUrl: url,
      document: document.get(url)!,
    })
  }
  throw new Error(
    `Attempted to remote load context : '${url}', please cache instead`,
  )
})
