import { randomBytes } from "node:crypto";
import {
  AddressCard,
  Challenge,
  signAddressCard,
  signChallenge,
  solvePoW,
  validateChallenge,
} from "./admission.js";
import {
  ApiError,
  Client,
  GitHubUpgradeResponse,
  GuestRegistrationResponse,
  VerifiedRegistrationResponse,
} from "./client.js";
import { deviceFlowToken, DEFAULT_CLIENT_ID } from "./github.js";
import type { InstallationKey } from "./installation.js";

export const CLI_VERSION = "0.2.0";

export type AdmissionResult = GuestRegistrationResponse | VerifiedRegistrationResponse;

interface RegisterOptions {
  client: Client;
  installation: InstallationKey;
  serverOrigin: string;
  note: (message: string) => void;
  githubBase?: string;
  signal?: AbortSignal;
}

function idempotencyKey(): string {
  return randomBytes(24).toString("base64url");
}

function asUpgrade(error: unknown): GitHubUpgradeResponse | null {
  if (!(error instanceof ApiError) || error.status !== 428) return null;
  const d = error.details as unknown as Partial<GitHubUpgradeResponse>;
  if (
    d.action !== "github_auth_required" ||
    d.risk_tier !== "high" ||
    typeof d.registration_flow_id !== "string" ||
    typeof d.verification_uri !== "string" ||
    typeof d.expires_at !== "string"
  ) {
    return null;
  }
  return d as GitHubUpgradeResponse;
}

function validateUpgrade(flow: GitHubUpgradeResponse, origin: string): void {
  if (!/^flow_[A-Za-z0-9_-]+$/.test(flow.registration_flow_id)) {
    throw new Error("invalid GitHub registration flow id");
  }
  if (Date.parse(flow.expires_at) <= Date.now()) throw new Error("GitHub registration flow is expired");
  const uri = new URL(flow.verification_uri);
  if (uri.protocol !== "https:" || uri.username || uri.password) {
    throw new Error("unsafe GitHub verification URI");
  }
  // The flow itself is origin-bound server-side; retaining this argument makes
  // that trust boundary explicit at the call site.
  const server = new URL(origin);
  const loopback = ["127.0.0.1", "::1", "localhost"].includes(server.hostname);
  if (server.protocol !== "https:" && !(server.protocol === "http:" && loopback)) {
    throw new Error("unsafe registration server origin");
  }
}

function assertGuestResult(result: GuestRegistrationResponse, card: AddressCard, signature: string): void {
  if (
    !result.token ||
    result.identity_type !== "guest" ||
    result.verified !== false ||
    result.session_id !== card.session_id ||
    result.principal_id !== card.principal_id ||
    result.installation_id !== card.installation_id ||
    result.address_card?.identity_type !== card.identity_type ||
    result.address_card?.principal_id !== card.principal_id ||
    result.address_card?.installation_id !== card.installation_id ||
    result.address_card?.session_id !== card.session_id ||
    result.address_card?.verified !== card.verified ||
    result.address_card?.public_key !== card.public_key ||
    result.address_card?.expires_at !== card.expires_at ||
    result.address_card?.signature !== signature
  ) {
    throw new Error("Guest registration response binding mismatch");
  }
}

function assertVerifiedResult(result: VerifiedRegistrationResponse, card: AddressCard, signature: string): void {
  if (
    !result.token ||
    result.identity_type !== "github" ||
    result.verified !== true ||
    result.session_id !== card.session_id ||
    result.principal_id !== card.principal_id ||
    result.installation_id !== card.installation_id ||
    result.github_user_id !== card.github_user_id ||
    result.github_login !== card.github_login ||
    result.address_card?.identity_type !== card.identity_type ||
    result.address_card?.principal_id !== card.principal_id ||
    result.address_card?.installation_id !== card.installation_id ||
    result.address_card?.session_id !== card.session_id ||
    result.address_card?.verified !== card.verified ||
    result.address_card?.public_key !== card.public_key ||
    result.address_card?.github_user_id !== card.github_user_id ||
    result.address_card?.github_login !== card.github_login ||
    result.address_card?.signature !== signature
  ) {
    throw new Error("Verified registration response binding mismatch");
  }
}

async function finishVerified(
  flow: GitHubUpgradeResponse,
  options: RegisterOptions,
): Promise<VerifiedRegistrationResponse> {
  validateUpgrade(flow, options.serverOrigin);
  options.note("This registration needs GitHub verification.");
  let credential = await deviceFlowToken({
    clientId: flow.github_client_id || DEFAULT_CLIENT_ID,
    base: options.githubBase,
    expectedVerificationUri: flow.verification_uri,
    signal: options.signal,
    onCode: (code, uri) => {
      options.note(`Open ${uri} and enter code ${code}.`);
      options.note("Waiting for authorization...");
    },
  });
  let challenge: Challenge;
  try {
    challenge = (await options.client.verifiedChallenge({
      registration_flow_id: flow.registration_flow_id,
      public_key: options.installation.publicKey,
      github_credential: credential,
    })) as Challenge;
  } finally {
    // Strings cannot be zeroized in JavaScript, but dropping the only DTO
    // reference immediately prevents persistence or accidental later logging.
    credential = "";
  }
  validateChallenge(challenge, options.serverOrigin, "verified_register");
  const card: AddressCard = {
    version: 2,
    service: challenge.server_origin,
    identity_type: "github",
    principal_id: challenge.principal_id,
    installation_id: challenge.installation_id,
    session_id: challenge.session_id,
    verified: true,
    public_key: options.installation.publicKey,
    github_user_id: challenge.github_user_id,
    github_login: challenge.github_login,
  };
  const addressCardSignature = signAddressCard(options.installation, card);
  const request = {
    registration_flow_id: flow.registration_flow_id,
    challenge_id: challenge.challenge_id,
    nonce: challenge.nonce,
    public_key: options.installation.publicKey,
    signature: signChallenge(options.installation, challenge),
    address_card_signature: addressCardSignature,
    idempotency_key: idempotencyKey(),
  };
  const result = await options.client.verifiedRegistration(request);
  assertVerifiedResult(result, card, addressCardSignature);
  return result;
}

export async function registerGuestFirst(options: RegisterOptions): Promise<AdmissionResult> {
  for (let challengeAttempt = 0; challengeAttempt < 3; challengeAttempt++) {
    let challenge: Challenge;
    try {
      challenge = (await options.client.guestChallenge({
        protocol_version: 1,
        public_key: options.installation.publicKey,
        client: {
          name: "agentmsg",
          version: CLI_VERSION,
          platform: process.platform,
          arch: process.arch,
        },
      })) as Challenge;
    } catch (error) {
      const upgrade = asUpgrade(error);
      if (upgrade) return finishVerified(upgrade, options);
      throw error;
    }
    validateChallenge(challenge, options.serverOrigin, "guest_register");
    let powSolution = "";
    let powElapsedMs = 0;
    if (challenge.risk_tier === "medium") {
      options.note(`Computing proof of work (${challenge.pow.difficulty_bits} bits)...`);
      const solved = await solvePoW(
        challenge.challenge_id,
        challenge.nonce,
        options.installation.publicKey,
        challenge.pow.difficulty_bits,
        {
          signal: options.signal,
          timeoutMs: Math.max(1, Math.min(120_000, Date.parse(challenge.expires_at) - Date.now() - 1000)),
          onProgress: (attempts) => options.note(`Proof of work: ${attempts} attempts...`),
        },
      );
      powSolution = solved.solution;
      powElapsedMs = solved.elapsedMs;
    }
    const card: AddressCard = {
      version: 1,
      service: challenge.server_origin,
      identity_type: "guest",
      principal_id: challenge.principal_id,
      installation_id: challenge.installation_id,
      session_id: challenge.session_id,
      verified: false,
      expires_at: challenge.guest_expires_at,
      public_key: options.installation.publicKey,
    };
    const addressCardSignature = signAddressCard(options.installation, card);
    const request = {
      challenge_id: challenge.challenge_id,
      nonce: challenge.nonce,
      public_key: options.installation.publicKey,
      pow_solution: powSolution,
      pow_elapsed_ms: powElapsedMs,
      signature: signChallenge(options.installation, challenge, powSolution),
      address_card_signature: addressCardSignature,
      idempotency_key: idempotencyKey(),
    };
    try {
      const result = await options.client.guestRegistration(request);
      assertGuestResult(result, card, addressCardSignature);
      return result;
    } catch (error) {
      if (
        error instanceof ApiError &&
        (error.code === "challenge_expired" ||
          error.code === "pow_required" ||
          error.code === "github_auth_required")
      ) {
        continue;
      }
      throw error;
    }
  }
  throw new Error("registration could not complete within the retry limit");
}
