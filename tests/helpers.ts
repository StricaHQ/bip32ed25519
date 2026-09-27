import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { Bip32PrivateKey } from "../src/index";

export const H = 0x80000000;

export const hex = (bytes: Uint8Array): string => Buffer.from(bytes).toString("hex");

// plain Uint8Arrays, so nothing passes only because the input is a Buffer
export const fromHex = (value: string): Uint8Array => new Uint8Array(Buffer.from(value, "hex"));

export const fixture = <T>(name: string): T =>
  JSON.parse(readFileSync(new URL(`./fixtures/${name}`, import.meta.url), "utf8"));

export type Outputs = { xprv: string; xpub: string; publicKey: string; signature: string };

// the ed25519-bip32 crate's outputs for a path
export type GoldenVector = Outputs & {
  entropy: string;
  path: string;
  message: string;
};

// "m/1852'/1815'/0'" as [1852 + H, 1815 + H, H]
export const pathIndices = (path: string): Array<number> =>
  path
    .split("/")
    .slice(1)
    .map((segment) => (segment.endsWith("'") ? Number(segment.slice(0, -1)) + H : Number(segment)));

const roots = new Map<string, Promise<Bip32PrivateKey>>();

export const rootKey = (entropy: string): Promise<Bip32PrivateKey> => {
  if (!roots.has(entropy)) roots.set(entropy, Bip32PrivateKey.fromEntropy(fromHex(entropy)));
  return roots.get(entropy)!;
};

export const outputs = (key: Bip32PrivateKey, message: Uint8Array): Outputs => {
  const privateKey = key.toPrivateKey();
  return {
    xprv: hex(key.toBytes()),
    xpub: hex(key.toBip32PublicKey().toBytes()),
    publicKey: hex(privateKey.toPublicKey().toBytes()),
    signature: hex(privateKey.sign(message)),
  };
};

// a deterministic byte stream, SHA-512 in counter mode over a seed, so a failure reproduces
export const random = (seed: string) => {
  let block = new Uint8Array();
  let offset = 0;
  let counter = 0;
  const bytes = (n: number): Uint8Array => {
    const out = new Uint8Array(n);
    for (let i = 0; i < n; i += 1) {
      if (offset === block.length) {
        block = new Uint8Array(createHash("sha512").update(`${seed}/${counter}`).digest());
        counter += 1;
        offset = 0;
      }
      out[i] = block[offset];
      offset += 1;
    }
    return out;
  };
  const below = (n: number): number => new DataView(bytes(4).buffer).getUint32(0, true) % n;
  return { bytes, below };
};
