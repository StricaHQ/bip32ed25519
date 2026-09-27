<p align="center">
  <a href="https://strica.io/" target="_blank">
    <img src="https://docs.strica.io/images/logo.png" width="200">
  </a>
</p>

# @stricahq/bip32ed25519

[![npm](https://img.shields.io/npm/v/@stricahq/bip32ed25519.svg)](https://www.npmjs.com/package/@stricahq/bip32ed25519)
[![downloads](https://img.shields.io/npm/dm/@stricahq/bip32ed25519.svg)](https://www.npmjs.com/package/@stricahq/bip32ed25519)
[![node](https://img.shields.io/node/v/@stricahq/bip32ed25519.svg)](https://nodejs.org)
[![license](https://img.shields.io/npm/l/@stricahq/bip32ed25519.svg)](./LICENSE)

Cardano key derivation and signing for JavaScript.

- Root keys from a BIP-39 mnemonic's entropy, made the [CIP-3](https://github.com/cardano-foundation/CIPs/blob/master/CIP-0003/Icarus.md) (Icarus) way, with an optional passphrase
- Hardened and soft [BIP32-Ed25519](https://input-output-hk.github.io/adrestia/static/Ed25519_BIP.pdf) derivation, one index at a time or by a path like [CIP-1852](https://github.com/cardano-foundation/CIPs/tree/master/CIP-1852)'s `m/1852'/1815'/0'/0/0`
- Address keys from an account's public key alone, for watch-only wallets
- Ed25519 signing, and verification that agrees with the Cardano ledger
- Runs in Node.js and in browsers, no polyfills needed

The curve math and hashing come from the audited [@noble/curves](https://github.com/paulmillr/noble-curves) and [@noble/hashes](https://github.com/paulmillr/noble-hashes). Those are the only dependencies.

## v2 is a breaking change

v2 is not a drop-in upgrade. It is ESM-only and needs Node 22.12 or later, and keys, signatures and hashes are `Uint8Array` instead of `Buffer`.

Moving to v2 is the recommended path: it is faster than v1, carries two dependencies instead of six and no Node.js builtins, and it will get new features and fixes from here on.

### Migrating from v1

| v1 | v2 |
|---|---|
| `Buffer` in and out | `Uint8Array` out; `Buffer` still accepted as input |
| `bytes.toString("hex")` | `Buffer.from(bytes).toString("hex")` (on a `Uint8Array`, `toString("hex")` returns comma-separated numbers) |
| `publicKey.pubKey` | `publicKey.toBytes()` |
| deep imports from `@stricahq/bip32ed25519/dist/…` | the package root only |
| Node.js polyfills for browser bundles | no Node.js builtins |
| CommonJS package | ESM only, `require(esm)` on Node >= 22.12 |

## Installation

### yarn/npm

```sh
yarn add @stricahq/bip32ed25519
```

The package is ESM-only and needs Node 22.12 or later. You can still `require()` it from CommonJS:

```js
const { Bip32PrivateKey } = require("@stricahq/bip32ed25519");
```

If you compile TypeScript to CommonJS, that needs TypeScript 5.8 or later with `"module": "nodenext"`.

### Browser

```html
<script src="https://cdn.jsdelivr.net/npm/@stricahq/bip32ed25519/dist/index.min.js"></script>
<script>
  const { Bip32PrivateKey } = bip32ed25519;
</script>
```

The bundle puts everything on a `bip32ed25519` global. If you use a bundler instead, you won't need polyfills or aliases, because the package doesn't use any Node.js builtins.

## Deriving keys

Start with `fromEntropy`. It takes the entropy of a BIP-39 mnemonic, meaning the bytes the words encode rather than the words themselves, so run the mnemonic through a BIP-39 library first.

```js
import { Bip32PrivateKey } from "@stricahq/bip32ed25519";

const rootKey = await Bip32PrivateKey.fromEntropy(entropy);

// CIP-1852: m / purpose' / coin type' / account' / role / index
const accountKey = rootKey.derivePath("m/1852'/1815'/0'");
const paymentKey = accountKey.derivePath("0/0").toPrivateKey();
const stakeKey = accountKey.derivePath("2/0").toPrivateKey();

const publicKey = paymentKey.toPublicKey();
publicKey.toBytes(); // Uint8Array(32)
publicKey.hash();    // Uint8Array(28), Blake2b-224: the payment credential in an address
```

In a path, `'`, `h` and `H` all mark a hardened index. You can also derive one step at a time. Both of these lines give the same account key as above:

```js
import { HARDENED_OFFSET } from "@stricahq/bip32ed25519";

rootKey.deriveHardened(1852).deriveHardened(1815).deriveHardened(0);
rootKey.derive(HARDENED_OFFSET + 1852).derive(HARDENED_OFFSET + 1815).derive(HARDENED_OFFSET);
```

If the wallet has a passphrase (the optional second factor from CIP-3), pass it as a string or as bytes:

```js
const rootKey = await Bip32PrivateKey.fromEntropy(entropy, "passphrase");
```

Entropy of any length works. For a 24-word Trezor wallet, pass 33 bytes: the 32 bytes of entropy followed by the mnemonic's checksum byte. Trezor's firmware keeps the checksum in, a known quirk that [CIP-3](https://github.com/cardano-foundation/CIPs/blob/master/CIP-0003/Icarus.md#trezor) documents.

`fromEntropy` is async because it runs PBKDF2 with 4096 iterations through WebCrypto, which takes about 2 ms. Where `crypto.subtle` isn't available, such as on a page served over plain http, it falls back to a JavaScript implementation that takes about 30 ms.

### Watch-only wallets

You don't need private keys to generate addresses. An account's extended public key can derive all of its soft (non-hardened) children:

```js
const accountXpub = accountKey.toBip32PublicKey();
const addressKey = accountXpub.derivePath("0/5").toPublicKey(); // the public key of accountKey.derivePath("0/5")
```

Hardened children can't be derived from a public key, so asking for one throws. To store an xpub, `toBytes()` gives you its 64 bytes and `Bip32PublicKey.fromBytes()` loads them back.

## Signing

`sign` takes any bytes. To witness a Cardano transaction, you sign the 32-byte hash of its body.

```js
const signature = paymentKey.sign(txHash); // Uint8Array(64)
publicKey.verify(signature, txHash);       // true
```

### cardano-cli keys

A signing key from cardano-cli, like a `payment.skey` file, isn't an extended key. It's a plain 32-byte Ed25519 secret key: the hex in its `cborHex` after the leading `5820`, which is just the CBOR header for 32 bytes. Load it with `fromSecretKey` and it signs exactly like standard RFC 8032 Ed25519:

```js
import { PrivateKey } from "@stricahq/bip32ed25519";

const key = PrivateKey.fromSecretKey(secretKey);
```

The `PrivateKey` constructor takes the 64-byte extended form (kL ‖ kR), the one `toPrivateKey()` gives you. Pass it 32 bytes and it throws, pointing you to `fromSecretKey`.

### Which signatures `verify` accepts

Ed25519 verifiers disagree on some edge cases, so `verify` matches the one Cardano uses. It accepts exactly what libsodium's `crypto_sign_verify_detached` accepts, and that's what the ledger checks signatures with. If `verify` accepts a signature, so will the chain, and the other way around. A signature is valid when:

- S is less than the group order L
- neither R nor the public key is one of the small-order encodings libsodium rejects
- the public key is canonically encoded and is a point on the curve
- [S]B − [h]A encodes to exactly R's bytes, where h = SHA-512(R ‖ A ‖ M) mod L. This is the cofactorless equation, and it also rules out a non-canonical R.

For a signature that isn't 64 bytes, `verify` just returns `false`. It never throws because of what a signature contains. None of these rules matter for honestly made signatures, which every Ed25519 verifier accepts. They only settle crafted edge cases.

## Bytes and hex

Everything the package returns is a plain `Uint8Array`. Wherever it takes bytes, any `Uint8Array` works, including a Node.js `Buffer` or one from another realm, like a jsdom test environment.

There are no hex helpers. On Node, use `Buffer.from(bytes).toString("hex")`. Newer runtimes have `bytes.toHex()`. Or use whatever hex helper your project already has.

## Errors

Bad input throws instead of quietly giving you a wrong key. Every function checks its arguments and throws a `TypeError` naming the one that's wrong. Here's what each one accepts:

| Where | Accepts |
|---|---|
| any byte argument | a `Uint8Array`, so a string throws, like a mnemonic passed as entropy |
| `fromEntropy` | non-empty entropy, and a passphrase as a string or bytes |
| `Bip32PrivateKey` | 96 bytes (kL ‖ kR ‖ chain code), where kL has its 3 lowest bits and its highest bit clear and its second-highest bit set |
| `Bip32PublicKey` | 64 bytes (public key ‖ chain code), where the public key is a point on the curve |
| `PrivateKey` | 64 bytes (kL ‖ kR), with the same rule for kL |
| `PrivateKey.fromSecretKey` | 32 bytes |
| `PublicKey` | 32 bytes |
| `derive` | an integer from 0 to 2^32 − 1, where 2^31 and up are hardened |
| `deriveHardened` | an integer from 0 to 2^31 − 1 |
| `derivePath` | an optional `m`, then decimal indices separated by `/`. An index marked with `'`, `h` or `H` is hardened and must be below 2^31; the others must be below 2^32 |
| `Bip32PublicKey.derive`, `derivePath` | soft indices only. A hardened one throws a plain `Error` |

## Key material

Each class keeps its own private copy of the bytes you pass in, and `toBytes()` hands back a fresh copy every time, so changing an array afterwards never changes a key. The package logs nothing, and no error message ever includes key bytes. It doesn't try to wipe keys from memory, though, since JavaScript has no way to guarantee that.

## Benchmarks

Measured on an Apple M1 Pro with Node 24.13.0.

| Operation | ops/s |
|---|---|
| `deriveHardened` | 50,576 |
| `derive`, soft, children of one key | 51,590 |
| `derivePath("m/1852'/1815'/0'/0/i")` from the root key | 1,955 |
| `Bip32PublicKey.derive` | 6,521 |
| `toPublicKey` of a new `PrivateKey` | 4,959 |
| `sign`, 32 bytes | 4,652 |
| `sign`, 1 KB | 4,175 |
| `verify`, 32 bytes | 1,061 |

`fromEntropy` takes 1.9 ms. A key remembers its public key after computing it, so deriving many soft children of one key (which is what a wallet does for its addresses) only computes it once. Computing a public key and signing each take one constant-time scalar multiplication. That's done by noble, which also blinds the secret scalar.

The browser bundle is 50 KB minified, 19 KB gzipped.

## Tests

```sh
yarn test
```

The suite checks:

- keys and signatures on 2,000 paths, against the [ed25519-bip32](https://docs.rs/ed25519-bip32/) crate that CIP-3 names as its reference implementation
- the CIP-3 and RFC 8032 test vectors
- `verify` against libsodium's verdicts, on the [ed25519-speccheck](https://github.com/novifinancial/ed25519-speccheck) vectors and a fuzz

Run `yarn build` first and it also tests the build: it loads the package through Node's own ESM loader and through `require()`, and runs the browser bundle with no Node.js globals.

## API docs

The full API reference is at [docs.strica.io/lib/bip32ed25519](https://docs.strica.io/lib/bip32ed25519).

## Used by

[Typhon Wallet](https://typhonwallet.io)

# License

Copyright 2021 Strica

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
