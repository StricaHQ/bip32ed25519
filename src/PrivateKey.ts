import { Buffer } from "buffer";
import PublicKey from "./PublicKey";

const EDDSA = require("./ed25519e");

const eddsa = new EDDSA();

export default class PrivateKey {
  private privKey: Buffer;

  constructor(privKey: Buffer) {
    this.privKey = privKey;
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
