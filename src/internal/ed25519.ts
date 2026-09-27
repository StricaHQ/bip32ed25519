// The only module that imports @noble/curves.
import { ed25519 } from "@noble/curves/ed25519.js";
import { hexToBytes } from "@noble/curves/utils.js";
import { bytesEqual, concat, fromBigInt, toBigInt } from "./bytes";
import { sha512 } from "./hash";

const { Point } = ed25519;
// the order of the base point B
const L = Point.Fn.ORDER;
// the field prime, 2^255 - 19
const P = Point.Fp.ORDER;

/** A decoded curve point, to keep and reuse: decoding one takes a square root. */
export type CurvePoint = ReturnType<typeof Point.fromBytes>;

/** The point a canonical encoding stands for; throws for any other 32 bytes. */
export const decodePoint = (encoding: Uint8Array): CurvePoint => Point.fromBytes(encoding);

export const encodePoint = (point: CurvePoint): Uint8Array => point.toBytes();

/**
 * The public key of a scalar kL, (kL mod L)·B, with noble's constant-time multiplication. kL is
 * used as it is, not hashed. It is at least 2^254, above L, and multiply() takes scalars in
 * [1, L), so it is reduced first; the point is the same.
 */
export const scalarPublicKey = (kL: Uint8Array): Uint8Array =>
  Point.BASE.multiply(toBigInt(kL) % L).toBytes();

/** A + scalar·B, for public derivation, where every input is public. */
export const addScalarBase = (A: CurvePoint, scalar: bigint): CurvePoint =>
  A.add(Point.BASE.multiplyUnsafe(scalar % L));

/**
 * Whether kL has the bits every ed25519-bip32 scalar and clamped RFC 8032 scalar has: the three
 * lowest and the highest clear, the second highest set. ed25519-bip32 master keys also clear the
 * third highest, but derivation may set it.
 */
export const isClamped = (kL: Uint8Array): boolean =>
  (kL[0] & 0b0000_0111) === 0 && (kL[31] & 0b1100_0000) === 0b0100_0000;

/** RFC 8032 key expansion (section 5.1.5): SHA-512 of the seed, the first half clamped. */
export const expandSeed = (seed: Uint8Array): Uint8Array => {
  const key = sha512(seed);
  key[0] &= 0b1111_1000;
  key[31] &= 0b0111_1111;
  key[31] |= 0b0100_0000;
  return key;
};

/**
 * Ed25519 with an extended key kL ‖ kR (RFC 8032, section 5.1.6, from step 2): the nonce is
 * SHA-512(kR ‖ M), the scalar kL. With a key from expandSeed this is RFC 8032 Ed25519.
 */
export const sign = (key: Uint8Array, publicKey: Uint8Array, message: Uint8Array): Uint8Array => {
  const r = toBigInt(sha512(key.subarray(32, 64), message)) % L;
  const R = Point.BASE.multiply(r).toBytes();
  const k = toBigInt(sha512(R, publicKey, message)) % L;
  const S = (r + k * (toBigInt(key.subarray(0, 32)) % L)) % L;
  return concat(R, fromBigInt(S, 32));
};

// The encodings libsodium's ge25519_has_small_order blocks, compared without the sign bit: the
// points of order 1, 2, 4 and 8, and y = p and y = p + 1, non-canonical encodings of two of them
const SMALL_ORDER = [
  "0000000000000000000000000000000000000000000000000000000000000000",
  "0100000000000000000000000000000000000000000000000000000000000000",
  "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
  "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
  "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
  "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
  "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
].map(hexToBytes);

const hasSmallOrder = (encoding: Uint8Array): boolean =>
  SMALL_ORDER.some((blocked) => {
    let diff = (encoding[31] & 0x7f) ^ blocked[31];
    for (let i = 0; i < 31; i += 1) diff |= encoding[i] ^ blocked[i];
    return diff === 0;
  });

// y < p, whatever the sign bit
const isCanonical = (encoding: Uint8Array): boolean =>
  toBigInt(encoding.subarray(0, 31)) + (BigInt(encoding[31] & 0x7f) << 248n) < P;

/**
 * Ed25519 verification that accepts exactly what libsodium's crypto_sign_verify_detached accepts,
 * which is what the Cardano ledger verifies with:
 *
 * 1. S < L
 * 2. R is none of the small-order encodings libsodium blocks
 * 3. A is canonical, none of them either, and a curve point
 * 4. h = SHA-512(R ‖ A ‖ M) mod L, over the bytes as given
 * 5. [S]B − [h]A encodes to R's bytes: the cofactorless equation, which also rules out a
 *    non-canonical R
 *
 * Points of mixed order pass, as in libsodium. A signature or key of the wrong length is false.
 */
export const verify = (
  publicKey: Uint8Array,
  message: Uint8Array,
  signature: Uint8Array
): boolean => {
  if (publicKey.length !== 32 || signature.length !== 64) return false;
  const R = signature.subarray(0, 32);
  const S = toBigInt(signature.subarray(32, 64));
  if (S >= L || hasSmallOrder(R)) return false;
  if (!isCanonical(publicKey) || hasSmallOrder(publicKey)) return false;
  let A: CurvePoint;
  try {
    A = Point.fromBytes(publicKey);
  } catch {
    return false;
  }
  const h = toBigInt(sha512(R, publicKey, message)) % L;
  // public inputs only, so the faster variable-time multiplication
  return bytesEqual(Point.BASE.multiplyUnsafe(S).subtract(A.multiplyUnsafe(h)).toBytes(), R);
};
