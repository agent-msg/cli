import { createHash } from "node:crypto";
import type { InstallationKey } from "./installation.js";

export const GUEST_PROTOCOL_VERSION = 1;
export const MAX_POW_DIFFICULTY = 24;

export interface Challenge {
  challenge_id: string;
  nonce: string;
  server_origin: string;
  intended_action: "guest_register" | "verified_register";
  risk_tier: "low" | "medium" | "high";
  expires_at: string;
  guest_expires_at: string;
  principal_id: string;
  installation_id: string;
  session_id: string;
  github_user_id?: string;
  github_login?: string;
  pow: { algorithm: "none" | "sha256"; difficulty_bits: number };
}

export interface AddressCard {
  version: 1 | 2;
  service: string;
  identity_type: "guest" | "github";
  principal_id: string;
  installation_id: string;
  session_id: string;
  verified: boolean;
  expires_at?: string;
  public_key: string;
  github_user_id?: string;
  github_login?: string;
}

function putString(parts: Buffer[], value: string): void {
  const raw = Buffer.from(value, "utf8");
  const length = Buffer.alloc(4);
  length.writeUInt32BE(raw.length);
  parts.push(length, raw);
}

function putUint64(parts: Buffer[], value: bigint | number): void {
  const encoded = Buffer.alloc(8);
  encoded.writeBigUInt64BE(BigInt(value));
  parts.push(encoded);
}

// Canonicalize an RFC3339 timestamp to Go's UTC RFC3339Nano representation
// without losing sub-millisecond digits in JavaScript's Date.
export function rfc3339NanoUTC(input: string): string {
  const match = input.match(
    /^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d{1,9}))?(Z|[+-]\d{2}:\d{2})$/,
  );
  if (!match) throw new Error(`invalid RFC3339Nano timestamp: ${input}`);
  const fraction = (match[2] || "").padEnd(9, "0");
  const milliseconds = fraction.slice(0, 3) || "000";
  const parsed = new Date(`${match[1]}.${milliseconds}${match[3]}`);
  if (!Number.isFinite(parsed.getTime())) throw new Error(`invalid timestamp: ${input}`);
  const second = parsed.toISOString().slice(0, 19);
  const trimmed = fraction.replace(/0+$/, "");
  return `${second}${trimmed ? "." + trimmed : ""}Z`;
}

export function challengePayload(
  challenge: Challenge,
  publicKey: string,
  powSolution = "",
): Buffer {
  const parts: Buffer[] = [];
  putString(parts, "agentmsg-guest-registration-v1");
  putUint64(parts, GUEST_PROTOCOL_VERSION);
  putString(parts, challenge.challenge_id);
  putString(parts, challenge.nonce);
  putString(parts, challenge.server_origin);
  putString(parts, challenge.intended_action);
  putString(parts, publicKey);
  putString(parts, rfc3339NanoUTC(challenge.expires_at));
  putString(parts, challenge.pow.algorithm);
  putUint64(parts, challenge.pow.difficulty_bits);
  putString(parts, powSolution);
  putString(parts, challenge.principal_id);
  putString(parts, challenge.installation_id);
  putString(parts, challenge.session_id);
  putString(parts, rfc3339NanoUTC(challenge.guest_expires_at));
  return Buffer.concat(parts);
}

export function addressCardPayload(card: AddressCard): Buffer {
  const parts: Buffer[] = [];
  putString(parts, "agentmsg-address-card-v1");
  putUint64(parts, card.version);
  putString(parts, card.service);
  putString(parts, card.identity_type);
  putString(parts, card.principal_id);
  putString(parts, card.installation_id);
  putString(parts, card.session_id);
  putUint64(parts, card.verified ? 1 : 0);
  putString(parts, rfc3339NanoUTC(card.expires_at || "0001-01-01T00:00:00Z"));
  putString(parts, card.public_key);
  if (card.version >= 2) {
    putString(parts, card.github_user_id || "");
    putString(parts, card.github_login || "");
  }
  return Buffer.concat(parts);
}

export function powDigest(
  challengeID: string,
  nonce: string,
  publicKey: string,
  solution: bigint,
): Buffer {
  if (solution < 0n || solution > 0xffffffffffffffffn) throw new Error("PoW solution is outside uint64");
  const rawPublic = Buffer.from(publicKey, "base64url");
  if (rawPublic.length !== 32 || rawPublic.toString("base64url") !== publicKey) {
    throw new Error("non-canonical Ed25519 public key");
  }
  const encoded = Buffer.alloc(8);
  encoded.writeBigUInt64BE(solution);
  return createHash("sha256")
    .update("agentmsg-guest-pow-v1", "utf8")
    .update(challengeID, "utf8")
    .update(nonce, "utf8")
    .update(createHash("sha256").update(rawPublic).digest())
    .update(encoded)
    .digest();
}

export function leadingZeroBits(bytes: Uint8Array): number {
  let total = 0;
  for (const value of bytes) {
    if (value === 0) {
      total += 8;
      continue;
    }
    for (let mask = 0x80; mask && (value & mask) === 0; mask >>= 1) total++;
    break;
  }
  return total;
}

export interface PowOptions {
  signal?: AbortSignal;
  timeoutMs?: number;
  now?: () => number;
  onProgress?: (attempts: bigint) => void;
}

export async function solvePoW(
  challengeID: string,
  nonce: string,
  publicKey: string,
  difficulty: number,
  options: PowOptions = {},
): Promise<{ solution: string; elapsedMs: number }> {
  if (!Number.isInteger(difficulty) || difficulty <= 0 || difficulty > MAX_POW_DIFFICULTY) {
    throw new Error(`unsafe PoW difficulty: ${difficulty}`);
  }
  const now = options.now || Date.now;
  const started = now();
  const deadline = started + (options.timeoutMs ?? 120_000);
  let solution = 0n;
  let lastProgress = started;
  for (;;) {
    if (options.signal?.aborted) throw new Error("PoW cancelled");
    const current = now();
    if (current > deadline) throw new Error("PoW time budget exceeded");
    if (leadingZeroBits(powDigest(challengeID, nonce, publicKey, solution)) >= difficulty) {
      return { solution: solution.toString(10), elapsedMs: Math.max(0, now() - started) };
    }
    solution++;
    if ((solution & 0x3fffn) === 0n) {
      if (current - lastProgress >= 1000) {
        options.onProgress?.(solution);
        lastProgress = current;
      }
      await new Promise<void>((resolve) => setImmediate(resolve));
    }
  }
}

export function validateChallenge(
  challenge: Challenge,
  expectedOrigin: string,
  expectedAction: Challenge["intended_action"],
  now = Date.now(),
): void {
  if (challenge.server_origin !== expectedOrigin) throw new Error("challenge server origin mismatch");
  if (challenge.intended_action !== expectedAction) throw new Error("challenge action mismatch");
  if (!/^chl_[A-Za-z0-9_-]+$/.test(challenge.challenge_id)) throw new Error("invalid challenge id");
  if (!/^(gst|prn)_[A-Za-z0-9_-]+$/.test(challenge.principal_id)) throw new Error("invalid principal id");
  if (!/^ins_[A-Za-z0-9_-]+$/.test(challenge.installation_id)) throw new Error("invalid installation id");
  if (!/^ses_[A-Za-z0-9_-]+$/.test(challenge.session_id)) throw new Error("invalid session id");
  if (!challenge.nonce) throw new Error("empty challenge nonce");
  const expires = Date.parse(challenge.expires_at);
  const guestExpires = Date.parse(challenge.guest_expires_at);
  if (!Number.isFinite(expires) || expires <= now) throw new Error("challenge is expired");
  if (!Number.isFinite(guestExpires) || guestExpires <= expires) throw new Error("invalid challenge expiry order");
  const difficulty = challenge.pow?.difficulty_bits;
  if (!Number.isInteger(difficulty) || difficulty < 0 || difficulty > MAX_POW_DIFFICULTY) {
    throw new Error("unsafe PoW difficulty");
  }
  if (expectedAction === "verified_register") {
    if (challenge.risk_tier !== "high" || challenge.pow.algorithm !== "none" || difficulty !== 0) {
      throw new Error("invalid Verified challenge risk or PoW binding");
    }
  } else if (challenge.risk_tier === "low") {
    if (challenge.pow.algorithm !== "none" || difficulty !== 0) throw new Error("low-risk challenge requested PoW");
  } else if (challenge.risk_tier === "medium") {
    if (challenge.pow.algorithm !== "sha256" || difficulty <= 0) throw new Error("medium-risk challenge omitted PoW");
  } else {
    throw new Error("invalid Guest risk tier");
  }
}

export function signChallenge(
  key: InstallationKey,
  challenge: Challenge,
  powSolution = "",
): string {
  return key.sign(challengePayload(challenge, key.publicKey, powSolution));
}

export function signAddressCard(key: InstallationKey, card: AddressCard): string {
  return key.sign(addressCardPayload(card));
}
