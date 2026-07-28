import { readFile } from "node:fs/promises";
import { describe, expect, it } from "vitest";
import { challengePayload, signChallenge } from "../src/admission.js";
import { installationKeyFromSeed } from "../src/installation.js";

const vectorFile = process.env.AGENTMSG_ADMISSION_VECTOR_FILE;
const suite = vectorFile ? describe : describe.skip;

suite("shared Go/TypeScript admission vectors", () => {
  it("matches the server-owned golden fixture", async () => {
    const fixture = JSON.parse(await readFile(vectorFile!, "utf8")) as any;
    const seed = Buffer.from(fixture.private_key_seed, "base64url");
    const key = installationKeyFromSeed(seed);
    const vector = fixture.challenges[0];
    const challenge = {
      challenge_id: vector.challenge_id,
      nonce: vector.nonce,
      server_origin: vector.server_origin,
      intended_action: vector.intended_action,
      risk_tier: "low",
      expires_at: vector.expires_at,
      guest_expires_at: vector.guest_expires_at,
      principal_id: vector.principal_id,
      installation_id: vector.installation_id,
      session_id: vector.session_id,
      pow: { algorithm: vector.pow_algorithm, difficulty_bits: vector.pow_difficulty },
    } as const;
    expect(key.publicKey).toBe(fixture.public_key);
    expect(challengePayload(challenge, key.publicKey).toString("hex")).toBe(vector.payload_hex);
    expect(signChallenge(key, challenge)).toBe(vector.signature);
  });
});
