// E2EE core: libsodium sealed boxes (X25519 + XChaCha20-Poly1305).
// The private key never leaves this machine; the public key travels on the
// user's address card, exchanged out-of-band. The server never sees either —
// it carries only ciphertext (wire flag enc:"box1").
// libsodium-wrappers ships a broken ESM build (its .mjs imports a missing
// sibling), so load the working CommonJS entry explicitly via createRequire.
import { createRequire } from "node:module";
const _sodium = createRequire(import.meta.url)("libsodium-wrappers");

async function sodium() {
  await _sodium.ready;
  return _sodium;
}

export interface Keypair {
  /** base64 X25519 public key — share on your address card */
  publicKey: string;
  /** base64 X25519 private key — stays in AGENTMSG_HOME, mode 0600 */
  privateKey: string;
}

/** Generate one keypair per session (independent even on the same machine). */
export async function generateKeypair(): Promise<Keypair> {
  const s = await sodium();
  const kp = s.crypto_box_keypair();
  return {
    publicKey: s.to_base64(kp.publicKey, s.base64_variants.ORIGINAL),
    privateKey: s.to_base64(kp.privateKey, s.base64_variants.ORIGINAL),
  };
}

/** Encrypt plaintext to a recipient's public key. Fresh ephemeral key per call. */
export async function seal(plaintext: string, recipientPublicKeyB64: string): Promise<string> {
  const s = await sodium();
  const pk = s.from_base64(recipientPublicKeyB64, s.base64_variants.ORIGINAL);
  const ct = s.crypto_box_seal(s.from_string(plaintext), pk);
  return s.to_base64(ct, s.base64_variants.ORIGINAL);
}

/** Decrypt a sealed box with this session's keypair. Throws if not for us or tampered. */
export async function open(
  ciphertextB64: string,
  publicKeyB64: string,
  privateKeyB64: string,
): Promise<string> {
  const s = await sodium();
  const ct = s.from_base64(ciphertextB64, s.base64_variants.ORIGINAL);
  const pk = s.from_base64(publicKeyB64, s.base64_variants.ORIGINAL);
  const sk = s.from_base64(privateKeyB64, s.base64_variants.ORIGINAL);
  const pt = s.crypto_box_seal_open(ct, pk, sk); // throws on auth failure
  return s.to_string(pt);
}

/**
 * Seal raw bytes to a recipient's public key. Used for attachments: the file is
 * encrypted on THIS machine before upload, so the server stores only opaque
 * ciphertext it cannot read. Returns the raw ciphertext bytes to PUT.
 */
export async function sealBytes(bytes: Uint8Array, recipientPublicKeyB64: string): Promise<Uint8Array> {
  const s = await sodium();
  const pk = s.from_base64(recipientPublicKeyB64, s.base64_variants.ORIGINAL);
  return s.crypto_box_seal(bytes, pk);
}

/** Open a sealed byte blob (a downloaded attachment) with this session's keypair.
 *  Throws if the ciphertext is not sealed to us or has been tampered with. */
export async function openBytes(
  ciphertext: Uint8Array,
  publicKeyB64: string,
  privateKeyB64: string,
): Promise<Uint8Array> {
  const s = await sodium();
  const pk = s.from_base64(publicKeyB64, s.base64_variants.ORIGINAL);
  const sk = s.from_base64(privateKeyB64, s.base64_variants.ORIGINAL);
  return s.crypto_box_seal_open(ciphertext, pk, sk); // throws on auth failure
}

/** A fresh symmetric key for one shared context. Base64, shared with members
 *  by sealing it to each member's public key — never sent to the server bare. */
export async function generateContextKey(): Promise<string> {
  const s = await sodium();
  return s.to_base64(s.randombytes_buf(s.crypto_secretbox_KEYBYTES), s.base64_variants.ORIGINAL);
}

/** Encrypt with a shared context key. The nonce is prepended to the ciphertext,
 *  so callers hold one opaque string. */
export async function encryptSym(plaintext: string, keyB64: string): Promise<string> {
  const s = await sodium();
  const key = s.from_base64(keyB64, s.base64_variants.ORIGINAL);
  const nonce = s.randombytes_buf(s.crypto_secretbox_NONCEBYTES);
  const ct = s.crypto_secretbox_easy(s.from_string(plaintext), nonce, key);
  const joined = new Uint8Array(nonce.length + ct.length);
  joined.set(nonce);
  joined.set(ct, nonce.length);
  return s.to_base64(joined, s.base64_variants.ORIGINAL);
}

export async function decryptSym(ciphertextB64: string, keyB64: string): Promise<string> {
  const s = await sodium();
  const key = s.from_base64(keyB64, s.base64_variants.ORIGINAL);
  const raw = s.from_base64(ciphertextB64, s.base64_variants.ORIGINAL);
  const nonce = raw.slice(0, s.crypto_secretbox_NONCEBYTES);
  const ct = raw.slice(s.crypto_secretbox_NONCEBYTES);
  return s.to_string(s.crypto_secretbox_open_easy(ct, nonce, key));
}
