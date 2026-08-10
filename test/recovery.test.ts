import { describe, it, expect } from "vitest";
import { encodeRecoveryCode, decodeRecoveryCode } from "../src/recovery.js";
import { generateContextKey } from "../src/crypto.js";

describe("recovery code", () => {
  it("round-trips a freshly generated context key", async () => {
    const key = await generateContextKey();
    const code = encodeRecoveryCode(key);
    expect(decodeRecoveryCode(code)).toBe(key);
  });

  it("round-trips many random keys (not a fluke of one value)", async () => {
    for (let i = 0; i < 25; i++) {
      const key = await generateContextKey();
      expect(decodeRecoveryCode(encodeRecoveryCode(key))).toBe(key);
    }
  });

  it("produces a clearly-delimited string, not raw base64", async () => {
    const key = await generateContextKey();
    const code = encodeRecoveryCode(key);
    expect(code).toMatch(/^AMSC1-[0-9A-Z-]+$/);
    expect(code).toContain("-");
    // Not just the base64 key reformatted — a genuinely different encoding.
    expect(code).not.toContain(key);
  });

  it("tolerates lowercase and surrounding whitespace on decode", async () => {
    const key = await generateContextKey();
    const code = encodeRecoveryCode(key);
    expect(decodeRecoveryCode(`  ${code.toLowerCase()}  `)).toBe(key);
  });

  it("rejects a mistyped code with a clear error, not a raw exception", async () => {
    const key = await generateContextKey();
    const code = encodeRecoveryCode(key);
    // Flip the SECOND-to-last symbol, not the last one. generateContextKey()
    // is always crypto_secretbox_KEYBYTES (32 bytes); with the 2-byte
    // checksum that's a fixed 272-bit payload, which base32-encodes to 55
    // symbols where the final symbol carries only the checksum's last 2 real
    // bits plus 3 zero PADDING bits (base32Decode drops them — see
    // recovery.ts). Flipping "0"->"1" in that last symbol can toggle only a
    // padding bit, silently producing a still-valid code ~1/4 of the time
    // (this was flaky: `npx vitest run test/recovery.test.ts` alone always
    // passed, but the full suite failed here roughly 1 run in 4). The
    // second-to-last symbol sits entirely inside the checksum's real bits, so
    // flipping it always changes the transmitted checksum deterministically.
    const idx = code.length - 2;
    const flipped = code.slice(0, idx) + (code[idx] === "0" ? "1" : "0") + code.slice(idx + 1);
    expect(() => decodeRecoveryCode(flipped)).toThrow(/checksum|mismatch|invalid/i);
  });

  it("rejects garbage input with a clear error", () => {
    expect(() => decodeRecoveryCode("not a real code")).toThrow();
    expect(() => decodeRecoveryCode("")).toThrow();
  });

  it("two different keys produce two different codes", async () => {
    const a = encodeRecoveryCode(await generateContextKey());
    const b = encodeRecoveryCode(await generateContextKey());
    expect(a).not.toBe(b);
  });
});
