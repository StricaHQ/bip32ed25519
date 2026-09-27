import { HARDENED_OFFSET } from "./derive";

const INDEX_LIMIT = 2 ** 32;

/** `index` if it is an integer from 0 to below `limit`, or a TypeError naming the argument. */
export const indexArgument = (index: unknown, name: string, limit = INDEX_LIMIT): number => {
  if (typeof index === "number" && Number.isInteger(index) && index >= 0 && index < limit) {
    return index;
  }
  const got = typeof index === "number" ? String(index) : typeof index;
  const max = limit === INDEX_LIMIT ? "2^32 - 1" : "2^31 - 1";
  throw TypeError(`${name} must be an integer from 0 to ${max}, got ${got}`);
};

const SEGMENT = /^(\d+)(['hH]?)$/;

/**
 * The indices of a derivation path such as "m/1852'/1815'/0'/0/0": an optional m, then indices
 * separated by /, each a decimal integer, hardened when followed by ', h or H. A hardened index
 * must be below 2^31 and has 2^31 added; a plain one must be below 2^32.
 */
export const parsePath = (path: unknown, name: string): Array<number> => {
  if (typeof path !== "string") throw TypeError(`${name} must be a string, got ${typeof path}`);
  const segments = path.split("/");
  if (segments[0] === "m") segments.shift();
  return segments.map((segment) => {
    const match = SEGMENT.exec(segment);
    if (!match) {
      throw TypeError(
        `${name}: ${JSON.stringify(path)} has ${JSON.stringify(segment)} where an index belongs`
      );
    }
    const index = Number(match[1]);
    const hardened = match[2] !== "";
    if (index >= (hardened ? HARDENED_OFFSET : INDEX_LIMIT)) {
      const limit = hardened ? "2^31 when hardened" : "2^32";
      throw TypeError(`${name}: index ${segment} of ${JSON.stringify(path)} is not below ${limit}`);
    }
    return hardened ? index + HARDENED_OFFSET : index;
  });
};
