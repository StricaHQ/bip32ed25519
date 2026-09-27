import { runInNewContext } from "node:vm";
import { beforeAll, describe, expect, it } from "vitest";
import {
  Bip32PrivateKey,
  Bip32PublicKey,
  HARDENED_OFFSET,
  PrivateKey,
  PublicKey,
} from "../src/index";
import { fromHex, hex } from "./helpers";

// Bad input throws a TypeError naming the argument, and never gives a key.

const ENTROPY = fromHex("46e62370a138a182a498b8e2885bc032379ddf38");
const MNEMONIC =
  "eight country switch draw meat scout mystery blade tip drift useless good keep usage title";

// kL with valid bits: the 3 lowest and the highest clear, the second highest set
const scalar = (): Uint8Array => {
  const kL = new Uint8Array(32).fill(0x5a);
  kL[0] = 0x58;
  kL[31] = 0x5a;
  return kL;
};

const notBytes: Array<[string, unknown]> = [
  ["a string", "00".repeat(32)],
  ["a number", 32],
  ["undefined", undefined],
  ["null", null],
  ["an array", Array.from({ length: 32 }, () => 0)],
  ["an ArrayBuffer", new ArrayBuffer(32)],
  ["a Uint16Array", new Uint16Array(32)],
  ["a Uint8ClampedArray", new Uint8ClampedArray(32)],
  ["an object", { length: 32 }],
];

describe("validation", (): void => {
  let root: Bip32PrivateKey;
  let xpub: Bip32PublicKey;
  let privateKey: PrivateKey;
  let publicKey: PublicKey;
  let signature: Uint8Array;

  beforeAll(async () => {
    root = await Bip32PrivateKey.fromEntropy(ENTROPY);
    xpub = root.toBip32PublicKey();
    privateKey = root.toPrivateKey();
    publicKey = privateKey.toPublicKey();
    signature = privateKey.sign(ENTROPY);
  });

  describe("byte arguments", (): void => {
    const calls = (): Array<[string, (value: any) => unknown]> => [
      ["Bip32PrivateKey: xprv", (value) => new Bip32PrivateKey(value)],
      ["Bip32PrivateKey: xprv", (value) => Bip32PrivateKey.fromBytes(value)],
      ["Bip32PublicKey: xpub", (value) => new Bip32PublicKey(value)],
      ["Bip32PublicKey: xpub", (value) => Bip32PublicKey.fromBytes(value)],
      ["PrivateKey: privateKey", (value) => new PrivateKey(value)],
      ["PrivateKey.fromSecretKey: secretKey", (value) => PrivateKey.fromSecretKey(value)],
      ["PublicKey: publicKey", (value) => new PublicKey(value)],
      ["PrivateKey.sign: message", (value) => privateKey.sign(value)],
      ["PrivateKey.verify: message", (value) => privateKey.verify(signature, value)],
      ["PrivateKey.verify: signature", (value) => privateKey.verify(value, ENTROPY)],
      ["PublicKey.verify: message", (value) => publicKey.verify(signature, value)],
      ["PublicKey.verify: signature", (value) => publicKey.verify(value, ENTROPY)],
    ];

    for (const [type, value] of notBytes) {
      it(`refuse ${type}`, () => {
        for (const [name, call] of calls()) {
          expect(() => call(value), name).toThrow(TypeError);
          expect(() => call(value), name).toThrow(`${name} must be a Uint8Array`);
        }
      });
    }

    it("refuse a mnemonic as entropy", async () => {
      await expect(Bip32PrivateKey.fromEntropy(MNEMONIC as any)).rejects.toThrow(TypeError);
      await expect(Bip32PrivateKey.fromEntropy(MNEMONIC as any)).rejects.toThrow(/mnemonic/);
    });

    it("take a Uint8Array from another realm, and a Buffer", async () => {
      const foreign = (bytes: Uint8Array): Uint8Array =>
        runInNewContext(`new Uint8Array([${bytes.join(",")}])`);
      expect(foreign(ENTROPY) instanceof Uint8Array).toBe(false);

      const fromForeign = await Bip32PrivateKey.fromEntropy(foreign(ENTROPY), foreign(ENTROPY));
      const fromBuffer = await Bip32PrivateKey.fromEntropy(
        Buffer.from(ENTROPY),
        Buffer.from(ENTROPY)
      );
      expect(hex(fromForeign.toBytes())).toBe(hex(fromBuffer.toBytes()));

      expect(hex(new Bip32PrivateKey(foreign(root.toBytes())).toBytes())).toBe(hex(root.toBytes()));
      expect(hex(new Bip32PublicKey(foreign(xpub.toBytes())).toBytes())).toBe(hex(xpub.toBytes()));
      expect(hex(new PrivateKey(foreign(privateKey.toBytes())).toBytes())).toBe(
        hex(privateKey.toBytes())
      );
      expect(hex(new PublicKey(foreign(publicKey.toBytes())).toBytes())).toBe(
        hex(publicKey.toBytes())
      );
      expect(hex(privateKey.sign(foreign(ENTROPY)))).toBe(hex(signature));
      expect(publicKey.verify(foreign(signature), foreign(ENTROPY))).toBe(true);
      expect(privateKey.verify(Buffer.from(signature), Buffer.from(ENTROPY))).toBe(true);
    });
  });

  describe("fromEntropy", (): void => {
    it("refuses empty entropy", async () => {
      await expect(Bip32PrivateKey.fromEntropy(new Uint8Array())).rejects.toThrow(TypeError);
    });

    it("takes entropy of any other length", async () => {
      for (const length of [1, 15, 33, 64, 100]) {
        const key = await Bip32PrivateKey.fromEntropy(new Uint8Array(length).fill(7));
        expect(key.toBytes()).toHaveLength(96);
      }
    });

    it("takes a passphrase as a string or bytes, and nothing else", async () => {
      const text = await Bip32PrivateKey.fromEntropy(ENTROPY, "foo");
      const bytes = await Bip32PrivateKey.fromEntropy(ENTROPY, new TextEncoder().encode("foo"));
      expect(hex(text.toBytes())).toBe(hex(bytes.toBytes()));
      expect(hex((await Bip32PrivateKey.fromEntropy(ENTROPY, "")).toBytes())).toBe(
        hex(root.toBytes())
      );
      for (const [, value] of notBytes.filter(([type]) => type !== "a string")) {
        if (value === undefined) continue; // the default
        await expect(Bip32PrivateKey.fromEntropy(ENTROPY, value as any)).rejects.toThrow(
          "Bip32PrivateKey.fromEntropy: passphrase must be a Uint8Array"
        );
      }
    });
  });

  describe("key bytes", (): void => {
    it("Bip32PrivateKey: 96 bytes", () => {
      for (const length of [0, 10, 64, 95, 97]) {
        expect(() => new Bip32PrivateKey(new Uint8Array(length))).toThrow(
          `Bip32PrivateKey expects 96 bytes, kL ‖ kR ‖ chain code, got ${length}`
        );
      }
    });

    it("PrivateKey: 64 bytes, and 32 point to fromSecretKey", () => {
      expect(() => new PrivateKey(new Uint8Array(32))).toThrow(/PrivateKey\.fromSecretKey/);
      for (const length of [0, 63, 65, 96]) {
        expect(() => new PrivateKey(new Uint8Array(length))).toThrow(
          `PrivateKey expects 64 bytes, got ${length}`
        );
      }
    });

    it("kL: the 3 lowest and the highest bit clear, the second highest set", () => {
      const keys = (kL: Uint8Array) => [
        () => new Bip32PrivateKey(Uint8Array.of(...kL, ...new Uint8Array(64))),
        () => new PrivateKey(Uint8Array.of(...kL, ...new Uint8Array(32))),
      ];

      for (const create of keys(scalar())) expect(create).not.toThrow();
      // the third highest bit is free: derivation may set it
      const third = scalar();
      third[31] |= 0b0010_0000;
      for (const create of keys(third)) expect(create).not.toThrow();

      for (const [bit, mask] of [
        [0, 0b0000_0001],
        [0, 0b0000_0010],
        [0, 0b0000_0100],
        [31, 0b1000_0000],
      ]) {
        const kL = scalar();
        kL[bit] |= mask;
        for (const create of keys(kL)) expect(create).toThrow(/kL has to have/);
      }
      const unset = scalar();
      unset[31] &= 0b1011_1111;
      for (const create of keys(unset)) expect(create).toThrow(/kL has to have/);
    });

    it("PrivateKey.fromSecretKey: 32 bytes", () => {
      for (const length of [0, 31, 33, 64]) {
        expect(() => PrivateKey.fromSecretKey(new Uint8Array(length))).toThrow(
          `PrivateKey.fromSecretKey expects 32 bytes, got ${length}`
        );
      }
    });

    it("PublicKey: 32 bytes", () => {
      for (const length of [0, 28, 31, 33, 64]) {
        expect(() => new PublicKey(new Uint8Array(length))).toThrow(
          `PublicKey expects 32 bytes, got ${length}`
        );
      }
    });

    it("Bip32PublicKey: 64 bytes, the first 32 a curve point", () => {
      for (const length of [0, 32, 63, 65, 96]) {
        expect(() => new Bip32PublicKey(new Uint8Array(length))).toThrow(
          `Bip32PublicKey expects 64 bytes, public key and chain code, got ${length}`
        );
      }
      const chainCode = xpub.toBytes().subarray(32);
      // y = 2 is not on the curve, and y = p is not canonical
      const notOnCurve = Uint8Array.of(2, ...new Uint8Array(31), ...chainCode);
      const nonCanonical = Uint8Array.of(
        0xed,
        ...new Uint8Array(30).fill(0xff),
        0x7f,
        ...chainCode
      );
      for (const bytes of [notOnCurve, nonCanonical]) {
        expect(() => new Bip32PublicKey(bytes)).toThrow(/not a public key/);
      }
    });

    it("errors never show key bytes", () => {
      const secret = root.toBytes();
      secret[0] |= 1;
      const attempts = [
        () => new Bip32PrivateKey(secret),
        () => new Bip32PrivateKey(secret.subarray(0, 95)),
        () => new PrivateKey(secret.subarray(0, 64)),
        () => new PrivateKey(secret.subarray(0, 32)),
        () => PrivateKey.fromSecretKey(secret.subarray(0, 33)),
        () => new Bip32PublicKey(Uint8Array.of(2, ...secret.subarray(1, 64))),
      ];
      for (const attempt of attempts) {
        let message = "";
        try {
          attempt();
        } catch (error) {
          message = (error as Error).message;
        }
        expect(message).not.toBe("");
        expect(message).not.toMatch(/[0-9a-f]{8}/);
      }
    });
  });

  describe("indices", (): void => {
    const bad: Array<unknown> = [
      -1,
      1.5,
      NaN,
      Infinity,
      -Infinity,
      2 ** 32,
      "5",
      5n,
      null,
      undefined,
    ];

    it("derive: an integer from 0 to 2^32 - 1", () => {
      for (const index of bad) {
        expect(() => root.derive(index as number)).toThrow(TypeError);
      }
      expect(() => root.derive(-1)).toThrow(
        "Bip32PrivateKey.derive: index must be an integer from 0 to 2^32 - 1, got -1"
      );
      expect(hex(root.derive(2 ** 32 - 1).toBytes())).toHaveLength(192);
      expect(hex(root.derive(0).toBytes())).toHaveLength(192);
    });

    it("deriveHardened: an integer from 0 to 2^31 - 1", () => {
      for (const index of [...bad, HARDENED_OFFSET, HARDENED_OFFSET + 5]) {
        expect(() => root.deriveHardened(index as number)).toThrow(TypeError);
      }
      expect(hex(root.deriveHardened(HARDENED_OFFSET - 1).toBytes())).toBe(
        hex(root.derive(2 ** 32 - 1).toBytes())
      );
    });

    it("Bip32PublicKey.derive: soft only", () => {
      for (const index of bad) {
        expect(() => xpub.derive(index as number)).toThrow(TypeError);
      }
      for (const index of [HARDENED_OFFSET, 2 ** 32 - 1]) {
        expect(() => xpub.derive(index)).toThrow("can not derive hardened public key");
      }
      expect(xpub.derive(HARDENED_OFFSET - 1).toBytes()).toHaveLength(64);
    });
  });

  describe("derivePath", (): void => {
    const derivations = (path: string) => [
      () => root.derivePath(path),
      () => xpub.derivePath(path),
    ];

    it("reads ', h and H as hardened", () => {
      const expected = hex(root.derivePath("m/1852'/1815'/0'").toBytes());
      for (const path of [
        "m/1852h/1815h/0h",
        "m/1852H/1815H/0H",
        "m/1852'/1815h/0H",
        "1852'/1815'/0'",
      ]) {
        expect(hex(root.derivePath(path).toBytes())).toBe(expected);
      }
      expect(hex(root.derivePath("m/1852'/1815'/0'").toBytes())).toBe(
        hex(root.deriveHardened(1852).deriveHardened(1815).deriveHardened(0).toBytes())
      );
    });

    it("takes m alone, an index without m, and indices up to their limits", () => {
      expect(hex(root.derivePath("m").toBytes())).toBe(hex(root.toBytes()));
      expect(hex(xpub.derivePath("m").toBytes())).toBe(hex(xpub.toBytes()));
      expect(hex(root.derivePath("0/5").toBytes())).toBe(hex(root.derive(0).derive(5).toBytes()));
      expect(hex(root.derivePath("m/2147483647'").toBytes())).toBe(
        hex(root.derive(2 ** 32 - 1).toBytes())
      );
      expect(hex(root.derivePath("m/4294967295").toBytes())).toBe(
        hex(root.derive(2 ** 32 - 1).toBytes())
      );
      expect(hex(xpub.derivePath("m/0/2147483647").toBytes())).toBe(
        hex(
          xpub
            .derive(0)
            .derive(HARDENED_OFFSET - 1)
            .toBytes()
        )
      );
    });

    it("refuses anything else", () => {
      for (const path of [
        "",
        "m/",
        "/0",
        "m//0",
        "m/0'/",
        "M/0",
        "m/m",
        "m/abc",
        "m/-1",
        "m/+1",
        "m/1.5",
        "m/1e3",
        "m/0x10",
        "m/ 0",
        "m/0 ",
        "m/0''",
        "m/0'h",
        "m/٣",
        "m/2147483648'",
        "m/4294967296",
      ]) {
        for (const derive of derivations(path)) expect(derive, path).toThrow(TypeError);
      }
      for (const path of [5, null, undefined, ["m", "0"]]) {
        expect(() => root.derivePath(path as any)).toThrow(TypeError);
        expect(() => xpub.derivePath(path as any)).toThrow(TypeError);
      }
    });

    it("Bip32PublicKey refuses a hardened step", () => {
      for (const path of ["m/0'", "0/1h", "0/2147483648"]) {
        expect(() => xpub.derivePath(path)).toThrow("can not derive hardened public key");
      }
    });
  });
});
