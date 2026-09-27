import { execFileSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { createContext, runInContext } from "node:vm";
import { beforeAll, describe, expect, it } from "vitest";
import * as bip32ed25519 from "../src/index";

// Checks the build as published, so run `yarn build` first; a check is skipped when its file is
// not built. The checks run outside vitest, whose module loader is more lenient than Node.js' own
// and than a browser, and import the package by its name, through the exports of package.json.
const root = fileURLToPath(new URL("../", import.meta.url));
const esm = `${root}dist/index.js`;
const iife = `${root}dist/index.min.js`;

const CIP3 =
  "c065afd2832cd8b087c4d9ab7011f481ee1e0721e78ea5dd609f3ab3f156d245d176bd8fd4ec60b4731c3918a2a72a0226c0cd119ec35b47e4d55884667f552a23f7fdcd4a10c6cd2c7393ac61d877873e248f417634aa3d812af327ffe9d620";
const CIP3_FOO =
  "70531039904019351e1afb361cd1b312a4d0565d4ff9f8062d38acf4b15cce41d7b5738d9c893feea55512a3004acb0d222c35d3e3d5cde943a15a9824cbac59443cf67e589614076ba01e354b1a432e0e6db3b59e37fc56b5fb0222970a010e";

// web platform code only, run the same way everywhere, with Bip32PrivateKey in scope
const checks = `(async () => {
  const hex = (bytes) => Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
  const bytes = (text) => Uint8Array.from(text.match(/../g) ?? [], (b) => parseInt(b, 16));
  const entropy = bytes("46e62370a138a182a498b8e2885bc032379ddf38");
  const rootKey = await Bip32PrivateKey.fromEntropy(entropy);
  const key = rootKey.derivePath("m/1852'/1815'/0'/0/0");
  const privateKey = key.toPrivateKey();
  const message = bytes("a475ccfbd6e91b4a1e1ad7fe2c8ce5d2c52df1641920368f84bdc68b84bdc68b");
  const signature = privateKey.sign(message);
  const xpub = rootKey.derivePath("m/1852'/1815'/0'").toBip32PublicKey().derivePath("0/0");
  return [
    hex(rootKey.toBytes()),
    hex((await Bip32PrivateKey.fromEntropy(entropy, "foo")).toBytes()),
    hex(key.toBytes()),
    hex(xpub.toBytes()) === hex(key.toBip32PublicKey().toBytes()),
    hex(signature),
    privateKey.toPublicKey().verify(signature, message),
    privateKey.toPublicKey().verify(signature, bytes("00")),
  ];
})()`;

const node = (args: Array<string>): unknown =>
  JSON.parse(execFileSync(process.execPath, args, { cwd: root, encoding: "utf8" }));

describe("dist", (): void => {
  let expected: unknown;

  beforeAll(async () => {
    const run = new Function(...Object.keys(bip32ed25519), `return ${checks}`);
    expected = await run(...Object.values(bip32ed25519));
    expect((expected as Array<unknown>).slice(0, 2)).toEqual([CIP3, CIP3_FOO]);
    expect((expected as Array<unknown>).slice(3)).toEqual([
      true,
      (expected as Array<string>)[4],
      true,
      false,
    ]);
  });

  it.skipIf(!existsSync(esm))("Node.js' ESM loader", () => {
    const script = `
      import { Bip32PrivateKey } from "@stricahq/bip32ed25519";
      console.log(JSON.stringify(await ${checks}));
    `;
    expect(node(["--input-type=module", "-e", script])).toEqual(expected);
  });

  it.skipIf(!existsSync(esm))("require() from CommonJS", () => {
    const script = `
      const { Bip32PrivateKey } = require("@stricahq/bip32ed25519");
      ${checks}.then((result) => console.log(JSON.stringify(result)));
    `;
    expect(node(["--input-type=commonjs", "-e", script])).toEqual(expected);
  });

  describe.skipIf(!existsSync(iife))("the browser bundle, without Node.js globals", (): void => {
    const run = async (globals: Record<string, unknown>): Promise<unknown> => {
      // web platform globals only: no process, Buffer, global or require
      const context: Record<string, unknown> = {
        TextEncoder,
        TextDecoder,
        setTimeout,
        clearTimeout,
        ...globals,
      };
      context.self = context;
      context.window = context;
      createContext(context);
      runInContext(readFileSync(iife, "utf8"), context);
      const result = await runInContext(
        `const { Bip32PrivateKey } = bip32ed25519; ${checks}`,
        context
      );
      return JSON.parse(JSON.stringify(result));
    };

    it("with WebCrypto", async () => {
      expect(await run({ crypto: globalThis.crypto })).toEqual(expected);
    });

    it("without crypto.subtle, as on a page served over http", async () => {
      expect(await run({})).toEqual(expected);
    });
  });
});
