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
    // Flip one character near the end (still valid alphabet, wrong value).
    const flipped = code.slice(0, -1) + (code.at(-1) === "0" ? "1" : "0");
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
