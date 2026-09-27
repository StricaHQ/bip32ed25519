// The only module that imports @noble/hashes.
import { blake2b } from "@noble/hashes/blake2.js";
import { hmac } from "@noble/hashes/hmac.js";
import { pbkdf2Async } from "@noble/hashes/pbkdf2.js";
import { sha512 as nobleSha512 } from "@noble/hashes/sha2.js";

export const sha512 = (...chunks: Array<Uint8Array>): Uint8Array => {
  const hash = nobleSha512.create();
  for (const chunk of chunks) hash.update(chunk);
  return hash.digest();
};

export const hmacSha512 = (key: Uint8Array, ...chunks: Array<Uint8Array>): Uint8Array => {
  const mac = hmac.create(nobleSha512, key);
  for (const chunk of chunks) mac.update(chunk);
  return mac.digest();
};

export const blake2b224 = (data: Uint8Array): Uint8Array => blake2b(data, { dkLen: 28 });

/**
 * PBKDF2-HMAC-SHA512 on WebCrypto, which runs natively, about 15 times faster than JavaScript.
 * noble computes the same bytes where crypto.subtle is missing, as in insecure browser
 * contexts, or refuses the input.
 */
export const pbkdf2Sha512 = async (
  password: Uint8Array,
  salt: Uint8Array,
  iterations: number,
  length: number
): Promise<Uint8Array> => {
  const subtle = globalThis.crypto?.subtle;
  if (subtle) {
    try {
      // copies, since WebCrypto refuses views of a SharedArrayBuffer
      const key = await subtle.importKey("raw", new Uint8Array(password), "PBKDF2", false, [
        "deriveBits",
      ]);
      const bits = await subtle.deriveBits(
        { name: "PBKDF2", hash: "SHA-512", salt: new Uint8Array(salt), iterations },
        key,
        8 * length
      );
      return new Uint8Array(bits);
    } catch {
      // noble below
    }
  }
  return pbkdf2Async(nobleSha512, password, salt, { c: iterations, dkLen: length });
};
