import { describe, expect, it, vi } from "vitest";
import { ApiError, Client, type GuestChallengeResponse } from "../src/client.js";
import { registerGuestFirst } from "../src/guest.js";
import { installationKeyFromSeed } from "../src/installation.js";

const origin = "https://msg.example.test";
const installation = installationKeyFromSeed(Buffer.alloc(32, 7));

function challenge(overrides: Partial<GuestChallengeResponse> = {}): GuestChallengeResponse {
  return {
    challenge_id: "chl_client_test",
    nonce: "nonce-client-test",
    server_origin: origin,
    intended_action: "guest_register",
    risk_tier: "low",
    expires_at: new Date(Date.now() + 120_000).toISOString(),
    guest_expires_at: new Date(Date.now() + 86_400_000).toISOString(),
    principal_id: "gst_client",
    installation_id: "ins_client",
    session_id: "ses_client",
    pow: { algorithm: "none", difficulty_bits: 0 },
    ...overrides,
  };
}

describe("Guest-first registration orchestration", () => {
  it("signs and completes a low-risk registration without GitHub", async () => {
    const ch = challenge();
    let request: Record<string, unknown> = {};
    const client = {
      guestChallenge: vi.fn(async () => ch),
      guestRegistration: vi.fn(async (input: Record<string, unknown>) => {
        request = input;
        return {
          session_id: ch.session_id,
          token: "guest-token",
          principal_id: ch.principal_id,
          installation_id: ch.installation_id,
          identity_type: "guest" as const,
          verified: false as const,
          expires_at: ch.guest_expires_at,
          address_card: {
            version: 1,
            service: origin,
            identity_type: "guest" as const,
            principal_id: ch.principal_id,
            installation_id: ch.installation_id,
            session_id: ch.session_id,
            verified: false,
            expires_at: ch.guest_expires_at,
            public_key: installation.publicKey,
            signature: String(input.address_card_signature),
          },
        };
      }),
    } as unknown as Client;
    const result = await registerGuestFirst({
      client,
      installation,
      serverOrigin: origin,
      note: () => undefined,
    });
    expect(result.identity_type).toBe("guest");
    expect(request.pow_solution).toBe("");
    expect(request.idempotency_key).toMatch(/^[A-Za-z0-9_-]{20,}$/);
    expect(request.signature).toMatch(/^[A-Za-z0-9_-]{86}$/);
  });

  it("solves medium PoW and binds the canonical decimal solution", async () => {
    const ch = challenge({
      risk_tier: "medium",
      pow: { algorithm: "sha256", difficulty_bits: 1 },
    });
    let solution = "";
    const client = {
      guestChallenge: vi.fn(async () => ch),
      guestRegistration: vi.fn(async (input: Record<string, unknown>) => {
        solution = String(input.pow_solution);
        return {
          session_id: ch.session_id,
          token: "guest-token",
          principal_id: ch.principal_id,
          installation_id: ch.installation_id,
          identity_type: "guest" as const,
          verified: false as const,
          expires_at: ch.guest_expires_at,
          address_card: {
            version: 1,
            service: origin,
            identity_type: "guest" as const,
            principal_id: ch.principal_id,
            installation_id: ch.installation_id,
            session_id: ch.session_id,
            verified: false,
            expires_at: ch.guest_expires_at,
            public_key: installation.publicKey,
            signature: String(input.address_card_signature),
          },
        };
      }),
    } as unknown as Client;
    await registerGuestFirst({ client, installation, serverOrigin: origin, note: () => undefined });
    expect(solution).toMatch(/^(0|[1-9]\d*)$/);
  });

  it("recognizes only a complete structured 428 upgrade response", async () => {
    const client = {
      guestChallenge: vi.fn(async () => {
        throw new ApiError(428, "http_error", "verify", {
          risk_tier: "high",
          action: "github_auth_required",
          registration_flow_id: "bad",
          verification_uri: "https://github.com/login/device",
          expires_at: new Date(Date.now() + 60_000).toISOString(),
        });
      }),
    } as unknown as Client;
    await expect(
      registerGuestFirst({ client, installation, serverOrigin: origin, note: () => undefined }),
    ).rejects.toThrow(/flow id/);
  });

  it("rejects a response card whose signed service field was changed", async () => {
    const ch = challenge();
    const client = {
      guestChallenge: vi.fn(async () => ch),
      guestRegistration: vi.fn(async (input: Record<string, unknown>) => ({
        session_id: ch.session_id,
        token: "guest-token",
        principal_id: ch.principal_id,
        installation_id: ch.installation_id,
        identity_type: "guest" as const,
        verified: false as const,
        expires_at: ch.guest_expires_at,
        address_card: {
          version: 1,
          service: "https://tampered.example",
          identity_type: "guest" as const,
          principal_id: ch.principal_id,
          installation_id: ch.installation_id,
          session_id: ch.session_id,
          verified: false,
          expires_at: ch.guest_expires_at,
          public_key: installation.publicKey,
          signature: String(input.address_card_signature),
        },
      })),
    } as unknown as Client;
    await expect(
      registerGuestFirst({ client, installation, serverOrigin: origin, note: () => undefined }),
    ).rejects.toThrow(/response binding mismatch/);
  });
});
