// Recovery codes for shared-context keys (task R5). See
// docs/shared-context-keys.html §"恢复码：借用 AK/SK 的模式，但只借一半" in the
// server repo for the reasoning this file must not undo:
//
//   - API secrets can be stored server-side as a hash because the server
//     only ever VERIFIES them. A context key must be USED (to decrypt), and a
//     hash is one-way — so this code is generated CLIENT-SIDE, from the key
//     already sitting in memory, and is never uploaded anywhere. "Server
//     generates then discards" was explicitly rejected too: the server would
//     have known the key at the moment of generation, and a promise to
//     forget is not a guarantee.
//   - This module therefore has no network dependency at all — it is a pure
//     encode/decode over bytes already held locally.
//
// No BIP39 (or any) word list exists in this project's dependency tree, and
// this task must add no dependency — so the code is a delimited,
// Crockford-base32 string instead of mnemonic words. Crockford's alphabet
// drops the characters most often confused when handwritten or read back
// (I, L, O, U, and the digits that look like them), which is what
// legibility-on-paper actually depends on, independent of word aesthetics.
import { createHash } from "node:crypto";

const ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"; // Crockford base32 (32 symbols)
const PREFIX = "AMSC1"; // "AgentMsg Shared Context", format version 1
const CHECKSUM_BYTES = 2; // catches a mistyped/mis-transcribed code early; not a security boundary
const GROUP_SIZE = 5; // legibility only — five-character clusters are easy to read back over a call

function base32Encode(bytes: Uint8Array): string {
  let bits = 0;
  let value = 0;
  let out = "";
  for (const b of bytes) {
    value = (value << 8) | b;
    bits += 8;
    while (bits >= 5) {
      out += ALPHABET[(value >>> (bits - 5)) & 0x1f];
      bits -= 5;
    }
  }
  if (bits > 0) {
    out += ALPHABET[(value << (5 - bits)) & 0x1f];
  }
  return out;
}

function base32Decode(input: string): Uint8Array {
  let bits = 0;
  let value = 0;
  const out: number[] = [];
  for (const ch of input) {
    const idx = ALPHABET.indexOf(ch);
    if (idx === -1) {
      throw new Error(`invalid recovery code — unrecognized character "${ch}"`);
    }
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  // Any leftover bits are the zero-padding base32Encode added to fill out
  // the last symbol, not data — they are intentionally dropped here.
  return new Uint8Array(out);
}

function group(s: string, size: number): string {
  const parts: string[] = [];
  for (let i = 0; i < s.length; i += size) parts.push(s.slice(i, i + size));
  return parts.join("-");
}

/**
 * Encode a context key (base64, the same form ContextKeys stores) into a
 * recovery code. Pure, synchronous, and entirely local: it never touches the
 * network, and callers must never pass the result to anything that would
 * transmit it (see the module doc comment above for why that invariant
 * matters). A 2-byte checksum (leading bytes of SHA-256 over the raw key) is
 * folded in purely to catch a mistyped code with a clear error instead of a
 * silently wrong key — it is not a security mechanism.
 */
export function encodeRecoveryCode(keyB64: string): string {
  const key = Buffer.from(keyB64, "base64");
  const checksum = createHash("sha256").update(key).digest().subarray(0, CHECKSUM_BYTES);
  const payload = Buffer.concat([key, checksum]);
  return `${PREFIX}-${group(base32Encode(payload), GROUP_SIZE)}`;
}

/**
 * Decode a recovery code back into the base64 context key. Throws a clear,
 * specific Error (never lets a raw parsing exception through) when the code
 * is malformed or its checksum doesn't match — i.e. it was mistyped or
 * corrupted in transcription.
 */
export function decodeRecoveryCode(code: string): string {
  const upper = code.trim().toUpperCase();
  const withoutPrefix = upper.startsWith(PREFIX) ? upper.slice(PREFIX.length) : upper;
  const symbols = withoutPrefix.replace(/[^0-9A-Z]/g, "");
  if (!symbols) {
    throw new Error("invalid recovery code — empty or unrecognizable");
  }
  const raw = base32Decode(symbols);
  if (raw.length <= CHECKSUM_BYTES) {
    throw new Error("invalid recovery code — too short to contain a key");
  }
  const key = raw.subarray(0, raw.length - CHECKSUM_BYTES);
  const checksum = raw.subarray(raw.length - CHECKSUM_BYTES);
  const expected = createHash("sha256").update(key).digest().subarray(0, CHECKSUM_BYTES);
  if (!Buffer.from(checksum).equals(expected)) {
    throw new Error("invalid recovery code — checksum mismatch (it was likely mistyped or corrupted)");
  }
  return Buffer.from(key).toString("base64");
}
