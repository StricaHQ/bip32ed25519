import { ed25519 } from "@noble/curves/ed25519.js";
import { beforeAll, describe, expect, it } from "vitest";
import { Bip32PrivateKey, PrivateKey, PublicKey } from "../src/index";
import { fixture, fromHex, hex, random, type GoldenVector } from "./helpers";

// PublicKey.verify is to accept exactly what libsodium's crypto_sign_verify_detached accepts, the
// verifier of the Cardano ledger. Every verdict here is libsodium 1.0.22's.

type Speccheck = {
  vectors: Array<{
    case: number;
    message: string;
    publicKey: string;
    signature: string;
    libsodium: boolean;
  }>;
};

const L = ed25519.Point.Fn.ORDER;
const le = (value: bigint): Uint8Array => {
  const out = new Uint8Array(32);
  for (let i = 0; i < 32; i += 1) out[i] = Number((value >> BigInt(8 * i)) & 0xffn);
  return out;
};
const int = (bytes: Uint8Array): bigint => BigInt(`0x${hex(bytes.slice().reverse()) || "0"}`);

// the small-order encodings libsodium blocks, and the same with the sign bit set
const SMALL_ORDER = [
  "0000000000000000000000000000000000000000000000000000000000000000",
  "0100000000000000000000000000000000000000000000000000000000000000",
  "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
  "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
  "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
  "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
  "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
].flatMap((encoding) => {
  const signed = fromHex(encoding);
  signed[31] |= 0x80;
  return [fromHex(encoding), signed];
});

const ours = (publicKey: Uint8Array, message: Uint8Array, signature: Uint8Array): boolean =>
  new PublicKey(publicKey).verify(signature, message);

const expectLibsodium = (
  publicKey: Uint8Array,
  message: Uint8Array,
  signature: Uint8Array,
  verdict: boolean
): void => {
  expect(
    ours(publicKey, message, signature),
    `${hex(publicKey)} ${hex(signature)} ${hex(message)}`
  ).toBe(verdict);
};

const MESSAGE = fromHex("a475ccfbd6e91b4a1e1ad7fe2c8ce5d2c52df1641920368f84bdc68b84bdc68b");

describe("verify accepts what libsodium accepts", (): void => {
  let signer: PrivateKey;
  let publicKey: Uint8Array;
  let signature: Uint8Array;

  beforeAll(() => {
    signer = PrivateKey.fromSecretKey(
      fromHex("833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42")
    );
    publicKey = signer.toPublicKey().toBytes();
    signature = signer.sign(MESSAGE);
  });

  describe("ed25519-speccheck", (): void => {
    for (const vector of fixture<Speccheck>("speccheck.json").vectors) {
      it(`case ${vector.case}`, () => {
        expectLibsodium(
          fromHex(vector.publicKey),
          fromHex(vector.message),
          fromHex(vector.signature),
          vector.libsodium
        );
      });
    }
  });

  it("an honest signature", () => {
    expectLibsodium(publicKey, MESSAGE, signature, true);
  });

  it("S + kL", () => {
    const S = int(signature.subarray(32));
    for (const k of [1n, 2n, 15n]) {
      const other = Uint8Array.of(...signature.subarray(0, 32), ...le(S + k * L));
      expectLibsodium(publicKey, MESSAGE, other, false);
    }
  });

  it("the wrong length is false, not an error", () => {
    for (const length of [0, 32, 63, 65, 128]) {
      const other = new Uint8Array(length);
      other.set(signature.subarray(0, Math.min(length, 64)));
      expect(ours(publicKey, MESSAGE, other)).toBe(false);
    }
  });

  it("small-order R", () => {
    for (const R of SMALL_ORDER) {
      const other = Uint8Array.of(...R, ...signature.subarray(32));
      expectLibsodium(publicKey, MESSAGE, other, false);
    }
  });

  it("small-order A, whatever the signature", () => {
    for (const A of SMALL_ORDER) {
      expectLibsodium(A, MESSAGE, signature, false);
      // R = [S]B - [h]A holds for any small A when S = 0 and R is the same point
      expectLibsodium(A, MESSAGE, Uint8Array.of(...A, ...new Uint8Array(32)), false);
    }
  });

  it("A with y >= p", () => {
    for (let k = 0n; k < 19n; k += 1n) {
      const A = le(2n ** 255n - 19n + k);
      expectLibsodium(A, MESSAGE, signature, false);
    }
  });

  it("A with other y, on the curve or not", () => {
    const A = publicKey.slice();
    for (let i = 0; i < 64; i += 1) {
      A[0] = i;
      expect(() => ours(A, MESSAGE, signature)).not.toThrow();
      expectLibsodium(A, MESSAGE, signature, false);
    }
  });

  it("every golden signature", () => {
    for (const vector of fixture<Array<GoldenVector>>("golden.json")) {
      expectLibsodium(
        fromHex(vector.publicKey),
        fromHex(vector.message),
        fromHex(vector.signature),
        true
      );
    }
  });

  it("fuzz: flipped bits, and random keys and signatures", async () => {
    const rng = random("verify");
    const root = await Bip32PrivateKey.fromEntropy(rng.bytes(16));
    for (let n = 0; n < 300; n += 1) {
      const key =
        n % 2 === 0
          ? PrivateKey.fromSecretKey(rng.bytes(32))
          : root.derive(rng.below(2 ** 32)).toPrivateKey();
      const A = key.toPublicKey().toBytes();
      const message = rng.bytes(rng.below(100));
      const signed = key.sign(message);
      expectLibsodium(A, message, signed, true);

      const flipped = signed.slice();
      flipped[rng.below(64)] ^= 1 << rng.below(8);
      expectLibsodium(A, message, flipped, false);

      const flippedKey = A.slice();
      flippedKey[rng.below(32)] ^= 1 << rng.below(8);
      expectLibsodium(flippedKey, message, signed, false);

      if (message.length > 0) {
        const flippedMessage = message.slice();
        flippedMessage[rng.below(message.length)] ^= 1 << rng.below(8);
        expectLibsodium(A, flippedMessage, signed, false);
      }

      expectLibsodium(A, message, rng.bytes(64), false);
      expectLibsodium(rng.bytes(32), message, signed, false);
      // S below L but not the signature's
      expectLibsodium(
        A,
        message,
        Uint8Array.of(...signed.subarray(0, 32), ...le(int(rng.bytes(32)) % L)),
        false
      );
      // R one of the small-order encodings
      const R = SMALL_ORDER[rng.below(SMALL_ORDER.length)];
      expectLibsodium(A, message, Uint8Array.of(...R, ...signed.subarray(32)), false);
    }
  });
});
