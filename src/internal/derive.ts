// ed25519-bip32 key derivation, as CIP-3 specifies it for Cardano.
import { concat, fromBigInt, toBigInt, uint32LE } from "./bytes";
import { addScalarBase, encodePoint, scalarPublicKey, type CurvePoint } from "./ed25519";
import { hmacSha512, pbkdf2Sha512 } from "./hash";

/** 2^31: an index at or above it is hardened, one below it soft. */
export const HARDENED_OFFSET = 0x80000000;

const TWO_256 = 1n << 256n;

/**
 * The CIP-3 Icarus master key: PBKDF2-HMAC-SHA512 of the passphrase salted with the entropy, 4096
 * iterations, 96 bytes: kL ‖ kR ‖ chain code, with kL's bits set as CIP-3 specifies.
 */
export const masterKey = async (
  entropy: Uint8Array,
  passphrase: Uint8Array
): Promise<Uint8Array> => {
  const xprv = await pbkdf2Sha512(passphrase, entropy, 4096, 96);
  xprv[0] &= 0b1111_1000;
  xprv[31] &= 0b0001_1111;
  xprv[31] |= 0b0100_0000;
  return xprv;
};

/**
 * Private child derivation, for child `index` of an xprv: kL + 8·ZL, with ZL the first 28 bytes of
 * Z, not reduced; kR + ZR mod 2^256, with ZR the last 32 bytes of Z, written as 32 bytes whatever
 * its value; and the chain code from I. Z and I are HMAC-SHA512 keyed with the chain code, over
 * kL ‖ kR for a hardened index, tagged 0x00 for Z and 0x01 for I, or over the public key for a
 * soft one, tagged 0x02 and 0x03. `publicKey` gives the xprv's public key, which a caller may have
 * at hand.
 */
export const derivePrivate = (
  xprv: Uint8Array,
  index: number,
  publicKey: () => Uint8Array = () => scalarPublicKey(xprv.subarray(0, 32))
): Uint8Array => {
  const hardened = index >= HARDENED_OFFSET;
  const key = hardened ? xprv.subarray(0, 64) : publicKey();
  const chainCode = xprv.subarray(64, 96);
  const i = uint32LE(index);
  const z = hmacSha512(chainCode, Uint8Array.of(hardened ? 0x00 : 0x02), key, i);
  // each level adds less than 2^227, so kL outgrows 32 bytes, and fromBigInt throws, only after
  // more than 2^28 levels
  const kL = toBigInt(xprv.subarray(0, 32)) + 8n * toBigInt(z.subarray(0, 28));
  const kR = (toBigInt(xprv.subarray(32, 64)) + toBigInt(z.subarray(32, 64))) % TWO_256;
  return concat(
    fromBigInt(kL, 32),
    fromBigInt(kR, 32),
    hmacSha512(chainCode, Uint8Array.of(hardened ? 0x01 : 0x03), key, i).subarray(32)
  );
};

/**
 * Public child derivation, for a soft index: A + (8·ZL)·B, and the chain code from I. `point` is
 * the xpub's public key A, decoded; the child's comes back with it.
 */
export const derivePublic = (
  xpub: Uint8Array,
  point: CurvePoint,
  index: number
): { xpub: Uint8Array; point: CurvePoint } => {
  const A = xpub.subarray(0, 32);
  const chainCode = xpub.subarray(32, 64);
  const i = uint32LE(index);
  const z = hmacSha512(chainCode, Uint8Array.of(0x02), A, i);
  const child = addScalarBase(point, 8n * toBigInt(z.subarray(0, 28)));
  return {
    xpub: concat(encodePoint(child), hmacSha512(chainCode, Uint8Array.of(0x03), A, i).subarray(32)),
    point: child,
  };
};
