/**
 * Hash a string with SHA-256 algorithm.
 *
 * @param {string} str The string to be hashed.
 *
 * @returns {Promise<Uint8Array>} Resolve to the hash value.
 */
export async function sha256(str: string): Promise<Uint8Array> {
  const bytes = new TextEncoder().encode(str)
  const digest = await crypto.subtle.digest("SHA-256", bytes)
  return new Uint8Array(digest)
}

/**
 * Hash a string with SHA-384 algorithm.
 *
 * @param {string} str The string to be hashed.
 *
 * @returns {Promise<Uint8Array>} Resolve to the hash value.
 */
export async function sha384(str: string): Promise<Uint8Array> {
  const bytes = new TextEncoder().encode(str)
  const digest = await crypto.subtle.digest("SHA-384", bytes)
  return new Uint8Array(digest)
}
