import PublicKey from "./PublicKey";
import { bytesArgument } from "./internal/bytes";
import { expandSeed, isClamped, scalarPublicKey, sign, verify } from "./internal/ed25519";

/**
 * An Ed25519 private key in extended form, 64 bytes: the scalar kL, and kR, from which the signing
 * nonce is derived. `Bip32PrivateKey.toPrivateKey()` gives one, and `PrivateKey.fromSecretKey`
 * makes one from a 32-byte RFC 8032 secret key, such as a cardano-cli signing key.
 */
export default class PrivateKey {
  readonly #key: Uint8Array;

  #publicKey?: Uint8Array;

  /** @param privateKey - kL ‖ kR, 64 bytes, copied */
  constructor(privateKey: Uint8Array) {
    const key = bytesArgument(privateKey, "PrivateKey: privateKey");
    if (key.length === 32) {
      throw TypeError(
        "PrivateKey expects 64 bytes, got 32: use PrivateKey.fromSecretKey for a 32-byte secret key"
      );
    }
    if (key.length !== 64) throw TypeError(`PrivateKey expects 64 bytes, got ${key.length}`);
    if (!isClamped(key.subarray(0, 32))) {
      throw TypeError(
        "PrivateKey: kL has to have its 3 lowest bits and its highest bit clear, and its second highest bit set"
      );
    }
    this.#key = key.slice();
  }

  /**
   * The key for a 32-byte Ed25519 secret key (RFC 8032), such as a cardano-cli payment signing
   * key: expanded with SHA-512, so it signs as RFC 8032 Ed25519 does.
   */
  static fromSecretKey(secretKey: Uint8Array): PrivateKey {
    const seed = bytesArgument(secretKey, "PrivateKey.fromSecretKey: secretKey");
    if (seed.length !== 32) {
      throw TypeError(`PrivateKey.fromSecretKey expects 32 bytes, got ${seed.length}`);
    }
    return new PrivateKey(expandSeed(seed));
  }

  /** A copy of the key's 64 bytes. */
  toBytes(): Uint8Array {
    return this.#key.slice();
  }

  toPublicKey(): PublicKey {
    return new PublicKey(this.#publicKeyBytes());
  }

  /** The Ed25519 signature of `message`, 64 bytes. */
  sign(message: Uint8Array): Uint8Array {
    return sign(
      this.#key,
      this.#publicKeyBytes(),
      bytesArgument(message, "PrivateKey.sign: message")
    );
  }

  /** Whether `signature` is this key's signature of `message`, as `PublicKey.verify` decides. */
  verify(signature: Uint8Array, message: Uint8Array): boolean {
    return verify(
      this.#publicKeyBytes(),
      bytesArgument(message, "PrivateKey.verify: message"),
      bytesArgument(signature, "PrivateKey.verify: signature")
    );
  }

  #publicKeyBytes(): Uint8Array {
    this.#publicKey ??= scalarPublicKey(this.#key.subarray(0, 32));
    return this.#publicKey;
  }
}
