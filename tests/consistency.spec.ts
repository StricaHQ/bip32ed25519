import { describe, expect, it } from "vitest";
import { HARDENED_OFFSET } from "../src/index";
import { fixture, hex, pathIndices, rootKey, type GoldenVector } from "./helpers";

const golden = fixture<Array<GoldenVector>>("golden.json");

describe("public derivation equals the public half of private derivation", (): void => {
  for (const { entropy, path } of golden) {
    const indices = pathIndices(path);
    if (!indices.some((index) => index < HARDENED_OFFSET)) continue;

    it(`${entropy.slice(0, 8)} ${path}, at every soft step`, async () => {
      let parent = await rootKey(entropy);
      for (const index of indices) {
        const child = parent.derive(index);
        if (index < HARDENED_OFFSET) {
          expect(hex(parent.toBip32PublicKey().derive(index).toBytes())).toBe(
            hex(child.toBip32PublicKey().toBytes())
          );
        }
        parent = child;
      }
    });
  }

  it("Bip32PublicKey.derivePath", async () => {
    const account = (await rootKey(golden[0].entropy)).derivePath("m/1852'/1815'/0'");
    const xpub = account.toBip32PublicKey();
    const expected = hex(account.derivePath("0/5").toBip32PublicKey().toBytes());
    expect(hex(xpub.derivePath("0/5").toBytes())).toBe(expected);
    expect(hex(xpub.derivePath("m/0/5").toBytes())).toBe(expected);
    expect(hex(xpub.derive(0).derive(5).toBytes())).toBe(expected);
  });
});
