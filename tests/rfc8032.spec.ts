import { describe, expect, it } from "vitest";
import { PrivateKey } from "../src/index";
import { fixture, fromHex, hex } from "./helpers";

type Rfc8032 = {
  vectors: Array<{
    name: string;
    secretKey: string;
    publicKey: string;
    message: string;
    signature: string;
  }>;
};

// RFC 8032, section 7.1
const { vectors } = fixture<Rfc8032>("rfc8032.json");

describe("RFC 8032 Ed25519 through PrivateKey.fromSecretKey", (): void => {
  for (const vector of vectors) {
    it(vector.name, () => {
      const privateKey = PrivateKey.fromSecretKey(fromHex(vector.secretKey));
      const publicKey = privateKey.toPublicKey();
      expect(hex(publicKey.toBytes())).toBe(vector.publicKey);

      const signature = privateKey.sign(fromHex(vector.message));
      expect(hex(signature)).toBe(vector.signature);
      expect(publicKey.verify(fromHex(vector.signature), fromHex(vector.message))).toBe(true);
    });
  }
});
