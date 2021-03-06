/* eslint-disable no-bitwise */

import { Buffer } from "buffer";
import BN from "bn.js";
import { pbkdf2 } from "pbkdf2";
import Bip32PublicKey from "./Bip32PublicKey";
import PrivateKey from "./PrivateKey";
import { hmac512 } from "./utils";

const EDDSA = require("./ed25519e");

const eddsa = new EDDSA();

export default class Bip32PrivateKey {
  protected xprv: Buffer;

  constructor(xprv: Buffer) {
    this.xprv = xprv;
  }

  static fromEntropy(entropy: Buffer): Promise<Bip32PrivateKey> {
    return new Promise((resolve, reject) => {
      pbkdf2("", entropy, 4096, 96, "sha512", (err, xprv) => {
        if (err) {
          reject(err);
        }
        xprv[0] &= 248;
        xprv[31] &= 0x1f;
        xprv[31] |= 64;
        resolve(new Bip32PrivateKey(xprv));
      });
    });
  }

  derive(index: number) {
    const kl = this.xprv.slice(0, 32);
    const kr = this.xprv.slice(32, 64);
    const cc = this.xprv.slice(64, 96);

    let z;
    let i;
    if (index < 0x80000000) {
      const data = Buffer.allocUnsafe(1 + 32 + 4);
      data.writeUInt32LE(index, 1 + 32);

      const keyPair = eddsa.keyFromSecret(kl.toString("hex"));
      const vk = Buffer.from(keyPair.pubBytes());
      vk.copy(data, 1);

      data[0] = 0x02;
      z = hmac512(cc, data);
      data[0] = 0x03;
      i = hmac512(cc, data);
    } else {
      const data = Buffer.allocUnsafe(1 + 64 + 4);
      data.writeUInt32LE(index, 1 + 64);
      kl.copy(data, 1);
      kr.copy(data, 1 + 32);

      data[0] = 0x00;
      z = hmac512(cc, data);
      data[0] = 0x01;
      i = hmac512(cc, data);
    }

    const chainCode = i.slice(32, 64);
    const zl = z.slice(0, 32);
    const zr = z.slice(32, 64);

    const left = new BN(kl, 16, "le")
      .add(new BN(zl.slice(0, 28), 16, "le").mul(new BN(8)))
      .toArrayLike(Buffer, "le", 32);
    let right = new BN(kr, 16, "le")
      .add(new BN(zr, 16, "le"))
      .toArrayLike(Buffer, "le")
      .slice(0, 32);

    if (right.length !== 32) {
      right = Buffer.from(right.toString("hex").padEnd(32, "0"), "hex");
    }

    const xprv = Buffer.concat([left, right, chainCode]);
    return new Bip32PrivateKey(xprv);
  }

  toBip32PublicKey() {
    const keyPair = eddsa.keyFromSecret(this.xprv.slice(0, 32).toString("hex"));
    const vk = Buffer.from(keyPair.pubBytes());
    return new Bip32PublicKey(Buffer.concat([vk, this.xprv.slice(64, 96)]));
  }

  toBytes(): Buffer {
    return this.xprv;
  }

  toPrivateKey(): PrivateKey {
    const keyPair = eddsa.keyFromSecret(this.xprv.slice(0, 64));
    return new PrivateKey(Buffer.from(keyPair.privBytes()));
  }
}
