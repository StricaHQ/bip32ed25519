import { bytesArgument } from "./internal/bytes";
import { verify } from "./internal/ed25519";
import { blake2b224 } from "./internal/hash";

/** An Ed25519 public key, 32 bytes. */
export default class PublicKey {
  readonly #key: Uint8Array;

  /** @param publicKey - 32 bytes, copied */
  constructor(publicKey: Uint8Array) {
    const key = bytesArgument(publicKey, "PublicKey: publicKey");
    if (key.length !== 32) throw TypeError(`PublicKey expects 32 bytes, got ${key.length}`);
    this.#key = key.slice();
  }

  /** A copy of the key's 32 bytes. */
  toBytes(): Uint8Array {
    return this.#key.slice();
  }

  /** The Blake2b-224 hash of the key, 28 bytes: the key hash in Cardano addresses and witnesses. */
  hash(): Uint8Array {
    return blake2b224(this.#key);
  }

  /**
   * Whether `signature` is this key's Ed25519 signature of `message`, by the rules of libsodium,
   * which the Cardano ledger verifies with. A signature that is not 64 bytes is false.
   */
  verify(signature: Uint8Array, message: Uint8Array): boolean {
    return verify(
      this.#key,
      bytesArgument(message, "PublicKey.verify: message"),
      bytesArgument(signature, "PublicKey.verify: signature")
    );
  }
}
