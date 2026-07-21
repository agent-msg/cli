import { describe, it, expect } from "vitest";
import { generateKeypair, seal, open } from "../src/crypto.js";

describe("E2EE sealed box", () => {
  it("roundtrips a message to the recipient's public key", async () => {
    const alice = await generateKeypair();
    const ct = await seal("hello alice, 密文测试 🚀", alice.publicKey);
    expect(ct).not.toContain("hello"); // ciphertext, not plaintext
    const pt = await open(ct, alice.publicKey, alice.privateKey);
    expect(pt).toBe("hello alice, 密文测试 🚀");
  });

  it("generates independent keypairs per call (one per session)", async () => {
    const a = await generateKeypair();
    const b = await generateKeypair();
    expect(a.publicKey).not.toBe(b.publicKey);
    expect(a.privateKey).not.toBe(b.privateKey);
  });

  it("cannot be opened with a different session's key", async () => {
    const alice = await generateKeypair();
    const mallory = await generateKeypair();
    const ct = await seal("secret", alice.publicKey);
    await expect(open(ct, mallory.publicKey, mallory.privateKey)).rejects.toThrow();
  });

  it("rejects tampered ciphertext (authenticated encryption)", async () => {
    const alice = await generateKeypair();
    const ct = await seal("secret", alice.publicKey);
    const raw = Buffer.from(ct, "base64");
    raw[raw.length - 1] ^= 0xff; // flip a bit
    const tampered = raw.toString("base64");
    await expect(open(tampered, alice.publicKey, alice.privateKey)).rejects.toThrow();
  });

  it("keys and ciphertext are plain base64 strings (address-card friendly)", async () => {
    const kp = await generateKeypair();
    const b64 = /^[A-Za-z0-9+/]+=*$/;
    expect(kp.publicKey).toMatch(b64);
    expect(kp.privateKey).toMatch(b64);
    expect(await seal("x", kp.publicKey)).toMatch(b64);
  });

  it("each seal of the same plaintext yields distinct ciphertext (ephemeral keys)", async () => {
    const kp = await generateKeypair();
    const c1 = await seal("same", kp.publicKey);
    const c2 = await seal("same", kp.publicKey);
    expect(c1).not.toBe(c2);
    expect(await open(c1, kp.publicKey, kp.privateKey)).toBe("same");
    expect(await open(c2, kp.publicKey, kp.privateKey)).toBe("same");
  });
});
