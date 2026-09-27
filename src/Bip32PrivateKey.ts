import Bip32PublicKey from "./Bip32PublicKey";
import PrivateKey from "./PrivateKey";
import { bytesArgument, concat } from "./internal/bytes";
import { derivePrivate, HARDENED_OFFSET, masterKey } from "./internal/derive";
import { isClamped, scalarPublicKey } from "./internal/ed25519";
import { indexArgument, parsePath } from "./internal/path";

/**
 * An ed25519-bip32 extended private key, 96 bytes: kL ‖ kR ‖ chain code, derived as CIP-3
 * specifies for Cardano.
 */
export default class Bip32PrivateKey {
  readonly #xprv: Uint8Array;

  #publicKey?: Uint8Array;

  /** @param xprv - kL ‖ kR ‖ chain code, 96 bytes, copied */
  constructor(xprv: Uint8Array) {
    const bytes = bytesArgument(xprv, "Bip32PrivateKey: xprv");
    if (bytes.length !== 96) {
      throw TypeError(
        `Bip32PrivateKey expects 96 bytes, kL ‖ kR ‖ chain code, got ${bytes.length}`
      );
    }
    if (!isClamped(bytes.subarray(0, 32))) {
      throw TypeError(
        "Bip32PrivateKey: kL has to have its 3 lowest bits and its highest bit clear, and its second highest bit set"
      );
    }
    this.#xprv = bytes.slice();
  }

  /** @param xprv - kL ‖ kR ‖ chain code, 96 bytes, copied */
  static fromBytes(xprv: Uint8Array): Bip32PrivateKey {
    return new Bip32PrivateKey(xprv);
  }

  /**
   * The CIP-3 Icarus master key for BIP-39 entropy: the bytes a mnemonic encodes, of any length,
   * not the mnemonic itself.
   *
   * @param passphrase - the optional second factor, as UTF-8 text or bytes; none by default
   */
  static async fromEntropy(
    entropy: Uint8Array,
    passphrase: Uint8Array | string = new Uint8Array()
  ): Promise<Bip32PrivateKey> {
    const salt = bytesArgument(
      entropy,
      "Bip32PrivateKey.fromEntropy: entropy",
      " (a mnemonic has to be turned into its BIP-39 entropy first)"
    );
    if (salt.length === 0) throw TypeError("Bip32PrivateKey.fromEntropy: entropy is empty");
    const password =
      typeof passphrase === "string"
        ? new TextEncoder().encode(passphrase)
        : bytesArgument(passphrase, "Bip32PrivateKey.fromEntropy: passphrase");
    return new Bip32PrivateKey(await masterKey(salt, password));
  }

  /** The child at `index`, an integer below 2^32: hardened at 2^31 and above, soft below. */
  derive(index: number): Bip32PrivateKey {
    indexArgument(index, "Bip32PrivateKey.derive: index");
    return new Bip32PrivateKey(derivePrivate(this.#xprv, index, () => this.#publicKeyBytes()));
  }

  /** The hardened child at `index` + 2^31, for an integer `index` below 2^31. */
  deriveHardened(index: number): Bip32PrivateKey {
    indexArgument(index, "Bip32PrivateKey.deriveHardened: index", HARDENED_OFFSET);
    return this.derive(index + HARDENED_OFFSET);
  }

  /**
   * The key at a path such as `"m/1852'/1815'/0'/0/0"`: an optional m, then indices separated by
   * /, each marked hardened by ', h or H, or not.
   */
  derivePath(path: string): Bip32PrivateKey {
    return parsePath(path, "Bip32PrivateKey.derivePath: path").reduce<Bip32PrivateKey>(
      (key, index) => key.derive(index),
      this
    );
  }

  toBip32PublicKey(): Bip32PublicKey {
    return new Bip32PublicKey(concat(this.#publicKeyBytes(), this.#xprv.subarray(64, 96)));
  }

  /** A copy of the key's 96 bytes. */
  toBytes(): Uint8Array {
    return this.#xprv.slice();
  }

  /** The signing key, kL ‖ kR. */
  toPrivateKey(): PrivateKey {
    return new PrivateKey(this.#xprv.subarray(0, 64));
  }

  // every soft child needs it, and a wallet derives many from one key
  #publicKeyBytes(): Uint8Array {
    this.#publicKey ??= scalarPublicKey(this.#xprv.subarray(0, 32));
    return this.#publicKey;
  }
}
