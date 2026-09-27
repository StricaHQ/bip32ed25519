import { beforeAll, describe, expect, it } from "vitest";
import {
  Bip32PrivateKey,
  Bip32PublicKey,
  HARDENED_OFFSET,
  PrivateKey,
  PublicKey,
} from "../src/index";
import { fromHex, hex } from "./helpers";

const ENTROPY = "000102030405060708090a0b0c0d0e0f";

describe("API", (): void => {
  let root: Bip32PrivateKey;
  beforeAll(async () => {
    root = await Bip32PrivateKey.fromEntropy(fromHex(ENTROPY));
  });

  const keys = () => {
    const xprv = root.derivePath("m/1852'/1815'/0'");
    const privateKey = xprv.toPrivateKey();
    return {
      Bip32PrivateKey: [xprv, (bytes: Uint8Array) => new Bip32PrivateKey(bytes)],
      Bip32PublicKey: [xprv.toBip32PublicKey(), (bytes: Uint8Array) => new Bip32PublicKey(bytes)],
      PrivateKey: [privateKey, (bytes: Uint8Array) => new PrivateKey(bytes)],
      PublicKey: [privateKey.toPublicKey(), (bytes: Uint8Array) => new PublicKey(bytes)],
    } as const;
  };

  it("exports HARDENED_OFFSET", () => {
    expect(HARDENED_OFFSET).toBe(0x80000000);
    expect(hex(root.deriveHardened(5).toBytes())).toBe(
      hex(root.derive(HARDENED_OFFSET + 5).toBytes())
    );
  });

  it("toBytes returns a copy", () => {
    for (const [key] of Object.values(keys())) {
      const bytes = key.toBytes();
      const before = hex(bytes);
      bytes.fill(0);
      expect(hex(key.toBytes())).toBe(before);
    }
  });

  it("constructors copy their input", () => {
    for (const [key, create] of Object.values(keys())) {
      const bytes = key.toBytes();
      const copy = create(bytes);
      bytes.fill(0);
      expect(hex(copy.toBytes())).toBe(hex(key.toBytes()));
    }
  });

  it("returns plain Uint8Arrays, and takes Buffers", () => {
    for (const [key, create] of Object.values(keys())) {
      const fromBuffer = create(Buffer.from(key.toBytes()));
      expect(Object.getPrototypeOf(fromBuffer.toBytes())).toBe(Uint8Array.prototype);
      expect(hex(fromBuffer.toBytes())).toBe(hex(key.toBytes()));
    }
    const privateKey = root.toPrivateKey();
    const signature = privateKey.sign(Buffer.from("message"));
    expect(Object.getPrototypeOf(signature)).toBe(Uint8Array.prototype);
    expect(Object.getPrototypeOf(privateKey.toPublicKey().hash())).toBe(Uint8Array.prototype);
    expect(
      privateKey.toPublicKey().verify(Buffer.from(signature), new TextEncoder().encode("message"))
    ).toBe(true);
  });

  it("fromBytes equals the constructor", () => {
    const xprv = root.derive(1);
    expect(hex(Bip32PrivateKey.fromBytes(xprv.toBytes()).toBytes())).toBe(hex(xprv.toBytes()));
    const xpub = xprv.toBip32PublicKey();
    expect(hex(Bip32PublicKey.fromBytes(xpub.toBytes()).toBytes())).toBe(hex(xpub.toBytes()));
  });

  it("keeps key bytes out of reach", () => {
    for (const [key] of Object.values(keys())) {
      expect(Object.keys(key)).toEqual([]);
      expect(JSON.stringify(key)).toBe("{}");
    }
  });

  it("hash is the Blake2b-224 of the public key", () => {
    const publicKey = PrivateKey.fromSecretKey(
      fromHex("b7cbcc113d2fe1c6f97d858c2e512459b36034c67f630749567d8783757394c7")
    ).toPublicKey();
    expect(hex(publicKey.hash())).toBe("5ca51b304b1f79d92eada8c58c513e969458dcd27ce4f5bc47823ffa");
  });
});
