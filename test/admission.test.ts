import { describe, expect, it } from "vitest";
import {
  addressCardPayload,
  challengePayload,
  leadingZeroBits,
  powDigest,
  signAddressCard,
  signChallenge,
  solvePoW,
  type AddressCard,
  type Challenge,
} from "../src/admission.js";
import { installationKeyFromSeed } from "../src/installation.js";

const key = installationKeyFromSeed(Buffer.from("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", "hex"));
const common = {
  server_origin: "https://msg.example.test",
  expires_at: "2026-07-26T08:09:10.123456789Z",
  principal_id: "gst_vector",
  installation_id: "ins_vector",
  session_id: "ses_vector",
  guest_expires_at: "2026-07-27T08:09:10.987654321Z",
} as const;

describe("admission v1 protocol golden vectors", () => {
  it("matches the server's Guest low-risk vector byte-for-byte", () => {
    const challenge: Challenge = {
      ...common,
      challenge_id: "chl_guest_vector",
      nonce: "nonce_guest_vector",
      intended_action: "guest_register",
      risk_tier: "low",
      pow: { algorithm: "none", difficulty_bits: 0 },
    };
    expect(key.publicKey).toBe("A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg");
    expect(challengePayload(challenge, key.publicKey).toString("hex")).toBe(
      "0000001e6167656e746d73672d67756573742d726567697374726174696f6e2d763100000000000000010000001063686c5f67756573745f766563746f72000000126e6f6e63655f67756573745f766563746f720000001868747470733a2f2f6d73672e6578616d706c652e746573740000000e67756573745f72656769737465720000002b41364548765f504f454c3464634e3059353076416d57666b316a436270513166486479475a424a564d62670000001e323032362d30372d32365430383a30393a31302e3132333435363738395a000000046e6f6e650000000000000000000000000000000a6773745f766563746f720000000a696e735f766563746f720000000a7365735f766563746f720000001e323032362d30372d32375430383a30393a31302e3938373635343332315a",
    );
    expect(signChallenge(key, challenge)).toBe(
      "Lw-MNGGjWnAV1q0MAgFCft9PLdl-0aA5hayoW1EWqTvyvrOjjaLrE7T0BV2JukeLTd3hBsixjNYI--l2PkhPDw",
    );
    expect(signChallenge(key, { ...challenge, nonce: challenge.nonce + "-changed" })).not.toBe(
      "Lw-MNGGjWnAV1q0MAgFCft9PLdl-0aA5hayoW1EWqTvyvrOjjaLrE7T0BV2JukeLTd3hBsixjNYI--l2PkhPDw",
    );
  });

  it("matches medium PoW digest, canonical solution and signature", async () => {
    const challenge: Challenge = {
      ...common,
      challenge_id: "chl_medium_vector",
      nonce: "nonce_medium_vector",
      intended_action: "guest_register",
      risk_tier: "medium",
      pow: { algorithm: "sha256", difficulty_bits: 12 },
    };
    expect(powDigest(challenge.challenge_id, challenge.nonce, key.publicKey, 4679n).toString("hex")).toBe(
      "0005d472388505d94256023920e8d93da931d32733f0b73636466869bb297b51",
    );
    expect(leadingZeroBits(powDigest(challenge.challenge_id, challenge.nonce, key.publicKey, 4679n))).toBeGreaterThanOrEqual(12);
    expect(signChallenge(key, challenge, "4679")).toBe(
      "pfG4RbcDZzoLlp-jN96hCLhn21Lzx91hpVXG4CIyPXPZ5zehcUuHGQqLhwlo6M23jHEighDm5WO5dZDVksxtBg",
    );
    await expect(solvePoW(challenge.challenge_id, challenge.nonce, key.publicKey, 12)).resolves.toMatchObject({
      solution: "4679",
    });
  });

  it("matches Address Card v1 and v2 signatures", () => {
    const guest: AddressCard = {
      version: 1,
      service: common.server_origin,
      identity_type: "guest",
      principal_id: common.principal_id,
      installation_id: common.installation_id,
      session_id: common.session_id,
      verified: false,
      expires_at: common.guest_expires_at,
      public_key: key.publicKey,
    };
    expect(signAddressCard(key, guest)).toBe(
      "fVZluI_QQObOx0Djm8LbanqtE1dc43PFcl5oVX3DYzoPLp74e50lu4NFTWhzJnIU0APjEU81lSr1kWcb0GfoBw",
    );
    const verified: AddressCard = {
      ...guest,
      version: 2,
      identity_type: "github",
      principal_id: "prn_github_vector",
      verified: true,
      expires_at: undefined,
      github_user_id: "424242",
      github_login: "vector-user",
    };
    expect(addressCardPayload(verified).toString("hex")).toContain("766563746f722d75736572");
    expect(signAddressCard(key, verified)).toBe(
      "hzWF9jzIBnsdvLUYxaczXvHxMtK9dy32Z0dlWkk0N42enZOqvc4kUxOF5_E3cqTd-LhxnWr6BE0vlYZDN0hBAA",
    );
  });

  it("length-prefixes UTF-8 bytes rather than JavaScript characters", () => {
    const card: AddressCard = {
      version: 2,
      service: common.server_origin,
      identity_type: "github",
      principal_id: "prn_github_vector",
      installation_id: common.installation_id,
      session_id: common.session_id,
      verified: true,
      public_key: key.publicKey,
      github_user_id: "42",
      github_login: "猫",
    };
    const bytes = addressCardPayload(card);
    expect(bytes.subarray(bytes.length - 7).toString("hex")).toBe("00000003e78cab");
  });

  it("cancels PoW without leaving a background worker", async () => {
    const ctl = new AbortController();
    ctl.abort();
    await expect(
      solvePoW("chl_cancel", "nonce", key.publicKey, 24, { signal: ctl.signal }),
    ).rejects.toThrow(/cancelled/);
  });
});
