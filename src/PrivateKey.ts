import { Buffer } from "buffer";
import PublicKey from "./PublicKey";

const EDDSA = require("./ed25519e");
const hash = require("hash.js");

const eddsa = new EDDSA();

export default class PrivateKey {
  private privKey: Buffer;

  constructor(privKey: Buffer, extended: Boolean = true) {
    if (extended) {
      this.privKey = privKey;
    } else {
      let extendedSecret = hash.sha512().update(privKey).digest();
      extendedSecret[0] &= 0b1111_1000;
      extendedSecret[31] &= 0b0011_1111;
      extendedSecret[31] |= 0b0100_0000;
      this.privKey = extendedSecret;
    }
  }

  toBytes(): Buffer {
    return this.privKey;
  }

  toPublicKey(): PublicKey {
    const keyPair = eddsa.keyFromSecret(this.privKey);
    return new PublicKey(Buffer.from(keyPair.pubBytes()));
  }

  sign(data: Buffer): Buffer {
    const keyPair = eddsa.keyFromSecret(this.privKey);
    const signature = keyPair.sign(data.toString("hex"));
    return Buffer.from(signature.toBytes());
  }

  verify(signature: Buffer, message: Buffer) {
    const keyPair = eddsa.keyFromSecret(this.privKey);
    return keyPair.verify(message.toString("hex"), signature.toString("hex"));
  }
}
