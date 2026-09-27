// %TypedArray%.prototype[Symbol.toStringTag] reads the type name from the value's internal
// slots (undefined for anything but a typed array), so unlike instanceof it also recognises
// a Uint8Array from another realm
const typedArrayName = Object.getOwnPropertyDescriptor(
  Object.getPrototypeOf(Uint8Array.prototype),
  Symbol.toStringTag
)!.get!;

// any Uint8Array passes, subclasses such as Node.js' Buffer and other realms included
export const isBytes = (value: unknown): value is Uint8Array =>
  value instanceof Uint8Array || typedArrayName.call(value) === "Uint8Array";

// the same bytes as a plain Uint8Array of this realm, sharing the input's memory
export const plainView = (bytes: Uint8Array): Uint8Array =>
  bytes.constructor === Uint8Array
    ? bytes
    : new Uint8Array(bytes.buffer, bytes.byteOffset, bytes.byteLength);

const typeName = (value: unknown): string => {
  if (value === null) return "null";
  if (typeof value !== "object") return typeof value;
  return typedArrayName.call(value) ?? Object.prototype.toString.call(value).slice(8, -1);
};

const hints: Record<string, string> = {
  string: " (convert hex to bytes first)",
  ArrayBuffer: " (wrap it: new Uint8Array(buffer))",
};

/**
 * A byte argument as a plain Uint8Array of this realm, sharing its memory, or a TypeError that
 * names the argument. `hint` replaces the default advice for a string.
 */
export const bytesArgument = (value: unknown, name: string, hint?: string): Uint8Array => {
  if (isBytes(value)) return plainView(value);
  const type = typeName(value);
  const advice = type === "string" && hint !== undefined ? hint : (hints[type] ?? "");
  throw TypeError(`${name} must be a Uint8Array, got ${type}${advice}`);
};

export const concat = (...chunks: Array<Uint8Array>): Uint8Array => {
  let total = 0;
  for (const chunk of chunks) total += chunk.length;
  const out = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    out.set(chunk, offset);
    offset += chunk.length;
  }
  return out;
};

export const bytesEqual = (a: Uint8Array, b: Uint8Array): boolean => {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i += 1) diff |= a[i] ^ b[i];
  return diff === 0;
};

// little-endian, the byte order of every integer in ed25519 and ed25519-bip32
export const toBigInt = (bytes: Uint8Array): bigint => {
  let value = 0n;
  for (let i = bytes.length - 1; i >= 0; i -= 1) value = (value << 8n) | BigInt(bytes[i]);
  return value;
};

export const fromBigInt = (value: bigint, length: number): Uint8Array => {
  const out = new Uint8Array(length);
  let rest = value;
  for (let i = 0; i < length; i += 1) {
    out[i] = Number(rest & 0xffn);
    rest >>= 8n;
  }
  if (rest !== 0n) throw RangeError(`Integer does not fit in ${length} bytes`);
  return out;
};

export const uint32LE = (value: number): Uint8Array =>
  Uint8Array.of(value & 0xff, (value >>> 8) & 0xff, (value >>> 16) & 0xff, value >>> 24);
