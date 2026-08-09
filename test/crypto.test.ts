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

import { generateContextKey, encryptSym, decryptSym } from "../src/crypto.js";

describe("symmetric encryption (shared context content)", () => {
  it("round-trips text through a shared key", async () => {
    const key = await generateContextKey();
    const ct = await encryptSym("shared state", key);
    expect(ct).not.toContain("shared state");
    expect(await decryptSym(ct, key)).toBe("shared state");
  });

  it("produces a different ciphertext each time (fresh nonce)", async () => {
    const key = await generateContextKey();
    expect(await encryptSym("same", key)).not.toBe(await encryptSym("same", key));
  });

  it("refuses to decrypt with the wrong key", async () => {
    const ct = await encryptSym("secret", await generateContextKey());
    await expect(decryptSym(ct, await generateContextKey())).rejects.toThrow();
  });

  // A truncated or flipped byte must fail loudly, not return garbage.
  it("rejects tampered ciphertext", async () => {
    const key = await generateContextKey();
    const ct = await encryptSym("secret", key);
    const tampered = ct.slice(0, -4) + "AAAA";
    await expect(decryptSym(tampered, key)).rejects.toThrow();
  });
});
