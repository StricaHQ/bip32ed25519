import { describe, expect, it } from "vitest";
import { fixture, fromHex, hex, outputs, pathIndices, rootKey, type GoldenVector } from "./helpers";

// 2,000 paths, CIP-1852 and random ones of depth 1 to 8, from 16- to 32-byte entropies, with the
// keys and signatures the ed25519-bip32 crate gives
const golden = fixture<Array<GoldenVector>>("golden.json");

describe("golden vectors", (): void => {
  for (const vector of golden) {
    const { entropy, path, message, xprv, xpub, publicKey, signature } = vector;
    const expected = { xprv, xpub, publicKey, signature };

    it(`${entropy.slice(0, 8)} ${path}`, async () => {
      const root = await rootKey(entropy);
      const key = root.derivePath(path);
      expect(outputs(key, fromHex(message))).toEqual(expected);

      const stepwise = pathIndices(path).reduce((parent, index) => parent.derive(index), root);
      expect(hex(stepwise.toBytes())).toBe(expected.xprv);
    });
  }
});
