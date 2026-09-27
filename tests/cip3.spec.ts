import { afterEach, describe, expect, it, vi } from "vitest";
import { Bip32PrivateKey } from "../src/index";
import { fromHex, hex } from "./helpers";

// https://github.com/cardano-foundation/CIPs/blob/master/CIP-0003/Icarus.md#test-vectors
// "eight country switch draw meat scout mystery blade tip drift useless good keep usage title"
const ENTROPY = fromHex("46e62370a138a182a498b8e2885bc032379ddf38");
const KEY =
  "c065afd2832cd8b087c4d9ab7011f481ee1e0721e78ea5dd609f3ab3f156d245d176bd8fd4ec60b4731c3918a2a72a0226c0cd119ec35b47e4d55884667f552a23f7fdcd4a10c6cd2c7393ac61d877873e248f417634aa3d812af327ffe9d620";
const KEY_FOO =
  "70531039904019351e1afb361cd1b312a4d0565d4ff9f8062d38acf4b15cce41d7b5738d9c893feea55512a3004acb0d222c35d3e3d5cde943a15a9824cbac59443cf67e589614076ba01e354b1a432e0e6db3b59e37fc56b5fb0222970a010e";

const masterKey = async (passphrase?: Uint8Array | string): Promise<string> =>
  hex((await Bip32PrivateKey.fromEntropy(ENTROPY, passphrase)).toBytes());

describe("CIP-3 Icarus master key", (): void => {
  afterEach(() => {
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
  });

  it("without passphrase", async () => {
    expect(await masterKey()).toBe(KEY);
  });

  it.each([
    ["a string", "foo"],
    ["UTF-8 bytes", new TextEncoder().encode("foo")],
  ])("with passphrase foo, as %s", async (_, passphrase) => {
    expect(await masterKey(passphrase)).toBe(KEY_FOO);
  });

  it("on noble where crypto.subtle is missing", async () => {
    vi.stubGlobal("crypto", {});
    expect(await masterKey()).toBe(KEY);
    expect(await masterKey("foo")).toBe(KEY_FOO);
  });

  it("on noble where crypto.subtle refuses the input", async () => {
    vi.spyOn(globalThis.crypto.subtle, "importKey").mockRejectedValue(Error("refused"));
    expect(await masterKey()).toBe(KEY);
  });
});
