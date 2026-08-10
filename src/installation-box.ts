// The shared-context X25519 identity, derived from the installation seed.
//
// Split out from installation.ts (R4 clean-up flagged in R1 review): that file
// is imported by session.ts and context.ts purely for the synchronous,
// filesystem-only atomicWritePrivate() helper. installation.ts used to also
// carry this module's `await _sodium.ready` at module load, which meant any
// caller who only wanted atomicWritePrivate() paid for (and could be hung by)
// libsodium's WASM bootstrap. Keeping the sodium-dependent code in its own
// module means a WASM-init hang can never block a filesystem-only code path.
import { hkdfSync } from "node:crypto";
import { createRequire } from "node:module";

// libsodium-wrappers ships a broken ESM build (its .mjs imports a missing
// sibling); load the working CommonJS entry explicitly, same pattern as
// src/crypto.ts's sodium() helper. installationBoxKeys() must be synchronous
// (see its signature below), so we await readiness once at module load —
// ES2022 top-level await — rather than on every call. That top-level await
// now only blocks callers who actually import THIS module.
const _sodium = createRequire(import.meta.url)("libsodium-wrappers");
await _sodium.ready;

// Domain separation string for deriving the shared-context X25519 identity
// from the installation seed. Distinct from the Ed25519 signing identity by
// construction (HKDF, not conversion) — see rework-plan.md Task R1. A future
// derivation for a different purpose must use a different `info` string so it
// can never collide with this one.
const CONTEXT_BOX_KEY_INFO = "agentmsg/context/x25519/v1";

export interface InstallationBoxKeys {
  /** base64 X25519 public key, derived from the installation seed */
  publicKey: string;
  /** base64 X25519 private key, derived from the installation seed */
  privateKey: string;
}

/**
 * Derives a shared-context X25519 keypair from the installation seed.
 *
 * This is a *derivation*, not a conversion: the installation identity is
 * Ed25519 (signing) and sealed boxes need X25519 (encryption). Converting the
 * Ed25519 key with crypto_sign_ed25519_pk_to_curve25519 would reuse one key
 * for two purposes, entangling their independent security proofs. Instead we
 * run HKDF-SHA256 over the seed with a domain-separated `info` string and
 * feed the output into crypto_box_seed_keypair.
 *
 * Deterministic: the same seed always yields the same pair, which is what
 * lets every session on one machine derive identical context keys with no
 * syncing.
 */
export function installationBoxKeys(seed: Buffer): InstallationBoxKeys {
  if (seed.length !== 32) throw new Error("installation key seed must be 32 bytes");
  const okm = hkdfSync("sha256", seed, Buffer.alloc(0), CONTEXT_BOX_KEY_INFO, 32);
  const boxSeed = Buffer.from(okm);
  const kp = _sodium.crypto_box_seed_keypair(boxSeed);
  return {
    publicKey: _sodium.to_base64(kp.publicKey, _sodium.base64_variants.ORIGINAL),
    privateKey: _sodium.to_base64(kp.privateKey, _sodium.base64_variants.ORIGINAL),
  };
}
