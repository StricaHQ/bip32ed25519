import PublicKey from "./PublicKey";
import { bytesArgument } from "./internal/bytes";
import { derivePublic, HARDENED_OFFSET } from "./internal/derive";
import { decodePoint, type CurvePoint } from "./internal/ed25519";
import { indexArgument, parsePath } from "./internal/path";

// The points of the children derive() creates, for their constructor, which then needn't decode
// them again. Only derive() holds the bytes these are keyed with.
const childPoints = new WeakMap<Uint8Array, CurvePoint>();

/**
 * An ed25519-bip32 extended public key, 64 bytes: the public key and the chain code. It derives
 * soft children only.
 */
export default class Bip32PublicKey {
  readonly #xpub: Uint8Array;

  readonly #point: CurvePoint;

  /** @param xpub - public key ‖ chain code, 64 bytes, copied */
  constructor(xpub: Uint8Array) {
    const point = childPoints.get(xpub);
    if (point) {
      childPoints.delete(xpub);
      this.#xpub = xpub;
      this.#point = point;
      return;
    }

    const bytes = bytesArgument(xpub, "Bip32PublicKey: xpub");
    if (bytes.length !== 64) {
      throw TypeError(
        `Bip32PublicKey expects 64 bytes, public key and chain code, got ${bytes.length}`
      );
    }
    try {
      this.#point = decodePoint(bytes.subarray(0, 32));
    } catch {
      throw TypeError("Bip32PublicKey: the first 32 bytes are not a public key, a curve point");
    }
    this.#xpub = bytes.slice();
  }

  /** @param xpub - public key ‖ chain code, 64 bytes, copied */
  static fromBytes(xpub: Uint8Array): Bip32PublicKey {
    return new Bip32PublicKey(xpub);
  }

  /** The soft child at `index`, below 2^31. */
  derive(index: number): Bip32PublicKey {
    indexArgument(index, "Bip32PublicKey.derive: index");
    if (index >= HARDENED_OFFSET) throw Error("can not derive hardened public key");
    const child = derivePublic(this.#xpub, this.#point, index);
    childPoints.set(child.xpub, child.point);
    return new Bip32PublicKey(child.xpub);
  }

  /** The key at a path of soft indices, such as `"0/5"`. */
  derivePath(path: string): Bip32PublicKey {
    return parsePath(path, "Bip32PublicKey.derivePath: path").reduce<Bip32PublicKey>(
      (key, index) => key.derive(index),
      this
    );
  }

  toPublicKey(): PublicKey {
    return new PublicKey(this.#xpub.subarray(0, 32));
  }

  /** A copy of the key's 64 bytes. */
  toBytes(): Uint8Array {
    return this.#xpub.slice();
  }
}
