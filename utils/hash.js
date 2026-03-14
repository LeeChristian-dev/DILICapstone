/**
 * Generate a SHA-256 hex digest for the provided text.
 * @param {string} value
 * @returns {Promise<string>}
 */
export async function sha256Hex(value) {
  const source = String(value ?? "");
  const encoder = new TextEncoder();
  const data = encoder.encode(source);
  const digest = await crypto.subtle.digest("SHA-256", data);
  const bytes = Array.from(new Uint8Array(digest));

  return bytes.map((item) => item.toString(16).padStart(2, "0")).join("");
}