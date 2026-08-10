// HTTP client for the agent-msg server API. Pure transport — no crypto here;
// the CLI layer seals/opens message bodies around these calls. Mirrors the Go
// client's endpoints and error envelope.

import { InstallationId, GitHubUserId } from "./ids.js";

export interface ApiErrorBody {
  error: string;
  message?: string;
}

/** A server error carrying the stable machine code (e.g. "target_not_found"). */
export class ApiError extends Error {
  constructor(
    public status: number,
    public code: string,
    message: string,
    public details: Record<string, unknown> = {},
    public retryAfter = 0,
  ) {
    super(message);
    this.name = "ApiError";
  }
}

export interface RegisterResponse {
  session_id: string;
  token: string;
  github_login: string;
  github_user_id: string;
  installation_id: string;
}

export interface GuestChallengeRequest {
  protocol_version: number;
  public_key: string;
  client: { name: string; version: string; platform: string; arch: string };
}

export interface GuestChallengeResponse {
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

export interface AddressCardDTO {
  version: number;
  service: string;
  identity_type: "guest" | "github";
  principal_id: string;
  installation_id: string;
  session_id: string;
  verified: boolean;
  expires_at?: string;
  public_key: string;
  signature: string;
  github_user_id?: string;
  github_login?: string;
  // installation_box_key is this installation's X25519 public key (derived
  // from the installation seed via HKDF — see installation-box.ts), the key
  // shared-context envelopes must be sealed to. NOT public_key, which is
  // either the installation's Ed25519 admission-signing key or (legacy
  // /v1/register) unset. Absent on cards from installations that predate
  // this field.
  installation_box_key?: string;
}

export interface GuestRegistrationResponse {
  session_id: string;
  token: string;
  principal_id: string;
  installation_id: string;
  identity_type: "guest";
  verified: false;
  expires_at: string;
  address_card: AddressCardDTO;
}

export interface GitHubUpgradeResponse {
  risk_tier: "high";
  action: "github_auth_required";
  registration_flow_id: string;
  verification_uri: string;
  github_client_id?: string;
  message?: string;
  expires_at: string;
}

export interface VerifiedRegistrationResponse {
  session_id: string;
  token: string;
  principal_id: string;
  installation_id: string;
  identity_type: "github";
  verified: true;
  github_user_id: string;
  github_login: string;
  address_card: AddressCardDTO;
}

export interface AttachmentGet {
  filename: string;
  bytes: number;
  download_path: string;
}

export interface InboxMessage {
  seq: number;
  msg_id: string;
  from: string;
  text: string;
  /** encryption scheme; "" (or absent) = plaintext, "box1" = sealed box */
  enc?: string;
  attachments?: AttachmentGet[];
}

export interface InboxResponse {
  messages: InboxMessage[];
  cursor: number;
  next_cursor?: number;
  has_more?: boolean;
}

export interface InboxStreamOptions {
  after: number;
  signal?: AbortSignal;
}

export interface SendResponse {
  msg_id: string;
  seq: number;
  uploads?: { filename: string; put_url: string }[];
}

export interface BillingResponse {
  plan: string;
  subscription_status?: string;
  current_period_end?: string;
}

/** Declared attachment metadata. Bytes/sha256 describe the CIPHERTEXT that will
 *  be uploaded — the server never sees the plaintext. */
export interface AttachmentDTO {
  filename: string;
  mime: string;
  bytes: number;
  sha256: string;
}

export interface SendInput {
  to: string;
  text: string;
  enc?: string;
  attachments?: AttachmentDTO[];
}

export interface FeedbackInput {
  text: string;
  /** bug | feature | other. Omitted lets the server apply its default. */
  kind?: string;
  /** CLI version + platform, so the operator can reproduce a reported bug. */
  client?: string;
}

export interface FeedbackResponse {
  feedback_id: string;
  kind: string;
  remaining_today: number;
}

export interface ContextDTO {
  id: string;
  name_enc: string;
  owner_uid: string;
  epoch: number;
  version: number;
  bytes: number;
  sha256?: string;
  updated_at: string;
  role?: string;
  download_url?: string;
  sealed_key?: string;
}

export interface PutContextResponse {
  upload_url: string;
  blob_key: string;
}

/** One outstanding authorisation: a member whose installation has no
 *  sealed-key envelope for the context's current epoch. Only returned by
 *  GET /v1/contexts/pending to a caller who already holds a key themselves —
 *  see api_context.go's handleListPendingContextKeys for why. */
export interface PendingKeyDTO {
  context_id: string;
  epoch: number;
  github_user_id: GitHubUserId;
  role: string;
  recipient_installation: InstallationId;
}

/** One sealed-key envelope, addressed to the recipient's installation id
 *  (never a session id — see the R2/R3 rework). */
export interface KeyEnvelope {
  recipient_installation: InstallationId;
  sealed_key: string;
}

/** Thrown on 409 so callers can merge rather than parse an error string. */
export class VersionConflict extends Error {
  constructor(public currentVersion: number) {
    super(`version conflict; current version is ${currentVersion}`);
    this.name = "VersionConflict";
  }
}

import { normalizeServerUrl } from "./serverurl.js";

const REQUEST_TIMEOUT_MS = 30_000;
const MAX_RESPONSE_BYTES = 8 << 20; // 8 MiB — well above any legitimate inbox page

// readCapped drains the body but aborts if it exceeds max, so an unbounded or
// hostile response can't grow memory without limit.
async function readCapped(resp: Response, max: number): Promise<string> {
  const cl = Number(resp.headers.get("content-length") || "");
  if (Number.isFinite(cl) && cl > max) throw new ApiError(0, "response_too_large", `response exceeds ${max} bytes`);
  if (!resp.body) return resp.text();
  const reader = resp.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > max) {
      await reader.cancel();
      throw new ApiError(0, "response_too_large", `response exceeds ${max} bytes`);
    }
    chunks.push(value);
  }
  return Buffer.concat(chunks).toString("utf8");
}

// Like readCapped but returns the raw bytes (for binary attachment downloads).
async function readCappedBytes(resp: Response, max: number): Promise<Uint8Array> {
  const cl = Number(resp.headers.get("content-length") || "");
  if (Number.isFinite(cl) && cl > max) throw new ApiError(0, "response_too_large", `response exceeds ${max} bytes`);
  if (!resp.body) return new Uint8Array(await resp.arrayBuffer());
  const reader = resp.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > max) {
      await reader.cancel();
      throw new ApiError(0, "response_too_large", `response exceeds ${max} bytes`);
    }
    chunks.push(value);
  }
  return Buffer.concat(chunks);
}

export class Client {
  public serverUrl: string;
  constructor(
    serverUrl: string,
    public token = "",
  ) {
    // Defense in depth (SEC-01): re-validate the origin here so no caller can
    // bypass the CLI-layer check and send the bearer token somewhere unsafe.
    // Loopback http is permitted (stays on the machine); remote http, userinfo,
    // and non-http(s) schemes are rejected unconditionally.
    this.serverUrl = normalizeServerUrl(serverUrl, true);
  }

  private async call<T>(
    method: string,
    path: string,
    body?: unknown,
    retryNetwork = false,
  ): Promise<T> {
    const attempts = retryNetwork ? 3 : 1;
    let lastError: unknown;
    for (let attempt = 0; attempt < attempts; attempt++) {
      try {
        return await this.callOnce<T>(method, path, body);
      } catch (error) {
        lastError = error;
        const retryable =
          error instanceof ApiError
            ? error.status === 0 && (error.code === "timeout" || error.code === "network_error")
            : false;
        if (!retryable || attempt + 1 >= attempts) throw error;
        await new Promise<void>((resolve) => setTimeout(resolve, 250 * 2 ** attempt));
      }
    }
    throw lastError;
  }

  private async callOnce<T>(method: string, path: string, body?: unknown): Promise<T> {
    const headers: Record<string, string> = {};
    if (this.token) headers["Authorization"] = `Bearer ${this.token}`;
    let payload: string | undefined;
    if (body !== undefined) {
      headers["Content-Type"] = "application/json";
      payload = JSON.stringify(body);
    }
    // HARD-01: bound the request in time and the response in size so a malicious
    // or wedged server can't hang the CLI or exhaust its memory.
    const ctl = new AbortController();
    const timer = setTimeout(() => ctl.abort(), REQUEST_TIMEOUT_MS);
    let resp: Response;
    try {
      resp = await fetch(this.serverUrl + path, { method, headers, body: payload, signal: ctl.signal });
    } catch (e) {
      clearTimeout(timer);
      if ((e as Error).name === "AbortError") throw new ApiError(0, "timeout", `request to ${path} timed out`);
      throw new ApiError(0, "network_error", `request to ${path} failed`);
    }
    clearTimeout(timer);
    const raw = await readCapped(resp, MAX_RESPONSE_BYTES);
    if (!resp.ok) {
      let code = "http_error";
      let msg = raw;
      let details: Record<string, unknown> = {};
      try {
        const e = JSON.parse(raw) as ApiErrorBody;
        details = e as unknown as Record<string, unknown>;
        code = e.error || code;
        msg = e.message || e.error || raw;
      } catch {
        /* non-JSON error body */
      }
      const retryAfter = Number(resp.headers.get("retry-after") || "0");
      throw new ApiError(resp.status, code, msg, details, Number.isFinite(retryAfter) ? retryAfter : 0);
    }
    return (raw ? JSON.parse(raw) : {}) as T;
  }

  register(credential: string): Promise<RegisterResponse> {
    return this.call("POST", "/v1/register", { credential });
  }

  guestChallenge(input: GuestChallengeRequest): Promise<GuestChallengeResponse> {
    return this.call("POST", "/v1/guest/challenges", input);
  }

  guestRegistration(input: Record<string, unknown>): Promise<GuestRegistrationResponse> {
    return this.call("POST", "/v1/guest/registrations", input, true);
  }

  verifiedChallenge(input: {
    registration_flow_id: string;
    public_key: string;
    github_credential: string;
  }): Promise<GuestChallengeResponse> {
    // If the response is lost after the server persisted verification, replay
    // this exact flow/key/token request before dropping the temporary token.
    return this.call("POST", "/v1/verified/challenges", input, true);
  }

  verifiedRegistration(input: Record<string, unknown>): Promise<VerifiedRegistrationResponse> {
    return this.call("POST", "/v1/verified/registrations", input, true);
  }

  addressCard(): Promise<AddressCardDTO> {
    return this.call("GET", "/v1/whoami/card");
  }

  unregister(): Promise<void> {
    return this.call("DELETE", "/v1/sessions/me");
  }

  send(input: SendInput): Promise<SendResponse> {
    const body: Record<string, unknown> = { to: input.to, text: input.text };
    if (input.enc) body.enc = input.enc;
    if (input.attachments && input.attachments.length) body.attachments = input.attachments;
    return this.call("POST", "/v1/messages", body);
  }

  /** Finalize a pending message once every attachment has been uploaded. */
  commit(msgID: string): Promise<{ msg_id: string; seq: number }> {
    return this.call("POST", `/v1/messages/${encodeURIComponent(msgID)}/commit`);
  }

  /** PUT ciphertext bytes to a presigned upload URL (may be a different origin,
   *  e.g. S3). No bearer token: the URL itself is the capability. */
  async uploadPut(putUrl: string, body: Uint8Array, mime: string): Promise<void> {
    const ctl = new AbortController();
    const timer = setTimeout(() => ctl.abort(), REQUEST_TIMEOUT_MS);
    let resp: Response;
    try {
      resp = await fetch(putUrl, { method: "PUT", headers: { "Content-Type": mime }, body: body as unknown as BodyInit, signal: ctl.signal });
    } catch (e) {
      clearTimeout(timer);
      if ((e as Error).name === "AbortError") throw new ApiError(0, "timeout", "attachment upload timed out");
      throw e;
    }
    clearTimeout(timer);
    if (!resp.ok) {
      const raw = await readCapped(resp, MAX_RESPONSE_BYTES).catch(() => "");
      throw new ApiError(resp.status, "upload_failed", `attachment upload failed (${resp.status}) ${raw}`);
    }
  }

  /** Download an attachment (raw ciphertext bytes) through the server, with auth. */
  async download(path: string): Promise<Uint8Array> {
    const headers: Record<string, string> = {};
    if (this.token) headers["Authorization"] = `Bearer ${this.token}`;
    const ctl = new AbortController();
    const timer = setTimeout(() => ctl.abort(), REQUEST_TIMEOUT_MS);
    let resp: Response;
    try {
      resp = await fetch(this.serverUrl + path, { method: "GET", headers, signal: ctl.signal });
    } catch (e) {
      clearTimeout(timer);
      if ((e as Error).name === "AbortError") throw new ApiError(0, "timeout", `download ${path} timed out`);
      throw e;
    }
    clearTimeout(timer);
    if (!resp.ok) {
      const raw = await readCapped(resp, MAX_RESPONSE_BYTES).catch(() => "");
      let code = "http_error";
      let msg = raw;
      try {
        const e = JSON.parse(raw) as ApiErrorBody;
        code = e.error || code;
        msg = e.message || e.error || raw;
      } catch {
        /* non-JSON error body */
      }
      throw new ApiError(resp.status, code, msg);
    }
    return readCappedBytes(resp, MAX_RESPONSE_BYTES);
  }

  inboxPage(after: number, limit = 0): Promise<InboxResponse> {
    let path = `/v1/inbox?after=${after}`;
    if (limit > 0) path += `&limit=${limit}`;
    return this.call("GET", path);
  }

  async *inboxStream(options: InboxStreamOptions): AsyncGenerator<InboxMessage> {
    const headers: Record<string, string> = { Accept: "text/event-stream" };
    if (this.token) headers["Authorization"] = `Bearer ${this.token}`;
    const path = `/v1/inbox/stream?after=${options.after}`;
    let resp: Response;
    try {
      resp = await fetch(this.serverUrl + path, { method: "GET", headers, signal: options.signal });
    } catch (e) {
      if ((e as Error).name === "AbortError") throw e;
      throw new ApiError(0, "network_error", `request to ${path} failed`);
    }
    if (!resp.ok) {
      const raw = await readCapped(resp, MAX_RESPONSE_BYTES).catch(() => "");
      let code = "http_error";
      let msg = raw;
      try {
        const e = JSON.parse(raw) as ApiErrorBody;
        code = e.error || code;
        msg = e.message || e.error || raw;
      } catch {
        /* non-JSON error body */
      }
      throw new ApiError(resp.status, code, msg);
    }
    if (!resp.body) throw new ApiError(0, "stream_unsupported", "server did not provide a response body");

    const reader = resp.body.getReader();
    const decoder = new TextDecoder();
    let buffer = "";
    let event = "";
    let data = "";
    const flush = function* (): Generator<InboxMessage> {
      if (event === "message" && data.trim()) yield JSON.parse(data) as InboxMessage;
      event = "";
      data = "";
    };
    try {
      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        buffer += decoder.decode(value, { stream: true });
        for (;;) {
          const idx = buffer.search(/\r?\n/);
          if (idx < 0) break;
          const line = buffer.slice(0, idx);
          buffer = buffer.slice(buffer[idx] === "\r" && buffer[idx + 1] === "\n" ? idx + 2 : idx + 1);
          if (line === "") {
            yield* flush();
          } else if (line.startsWith("event:")) {
            event = line.slice(6).trim();
          } else if (line.startsWith("data:")) {
            data += (data ? "\n" : "") + line.slice(5).trimStart();
          }
        }
      }
      buffer += decoder.decode();
      if (buffer.trim()) {
        for (const line of buffer.split(/\r?\n/)) {
          if (line === "") yield* flush();
          else if (line.startsWith("event:")) event = line.slice(6).trim();
          else if (line.startsWith("data:")) data += (data ? "\n" : "") + line.slice(5).trimStart();
        }
      }
      yield* flush();
    } finally {
      await reader.cancel().catch(() => {});
    }
  }

  ack(seq: number): Promise<unknown> {
    return this.call("POST", "/v1/inbox/ack", { seq });
  }

  setPolicy(mode: string, allow: string[], ackRisk: boolean): Promise<unknown> {
    return this.call("PUT", "/v1/policy", { mode, allow, i_understand_the_risk: ackRisk });
  }

  billing(): Promise<BillingResponse> {
    return this.call("GET", "/v1/billing");
  }

  /** Submit product feedback. NOT end-to-end encrypted: the operator is the
   *  recipient and has to be able to read it. */
  feedback(input: FeedbackInput): Promise<FeedbackResponse> {
    const body: Record<string, unknown> = { text: input.text };
    if (input.kind) body.kind = input.kind;
    if (input.client) body.client = input.client;
    return this.call("POST", "/v1/feedback", body);
  }

  checkout(): Promise<{ url: string }> {
    return this.call("POST", "/v1/billing/checkout");
  }

  portal(): Promise<{ url: string }> {
    return this.call("POST", "/v1/billing/portal");
  }

  createContext(nameEnc: string): Promise<ContextDTO> {
    return this.call("POST", "/v1/contexts", { name_enc: nameEnc });
  }

  listContexts(): Promise<ContextDTO[]> {
    return this.call("GET", "/v1/contexts");
  }

  getContext(id: string): Promise<ContextDTO> {
    return this.call("GET", `/v1/contexts/${encodeURIComponent(id)}`);
  }

  putContext(id: string, expectedVersion: number, bytes: number, sha256: string): Promise<PutContextResponse> {
    return this.call("PUT", `/v1/contexts/${encodeURIComponent(id)}`, {
      expected_version: expectedVersion, bytes, sha256,
    });
  }

  /** Finalise a write. Throws VersionConflict when another writer won.
   *
   *  Note on extraction: call() parses the JSON error envelope and stores the
   *  *whole* parsed body on ApiError.details (see callOnce's `details = e as
   *  unknown as Record<string, unknown>`). For this endpoint's 409 body,
   *  `{"error":"version_conflict","current_version":N}`, that means
   *  `error.details.current_version` holds N directly. ApiError.message does
   *  NOT contain the number here: callOnce sets `msg = e.message || e.error ||
   *  raw`, and since this envelope has no `message` field, msg falls back to
   *  `e.error`, i.e. the literal string "version_conflict" — no digits, no raw
   *  JSON. A regex over error.message (as the brief drafted) would always match
   *  nothing and silently default to version 0. Reading `details.current_version`
   *  is the only reliable path given what call() actually produces.
   *
   *  If the server's 409 body is missing `current_version` (or sends a
   *  non-number), we do NOT manufacture VersionConflict(0) — a fabricated
   *  version is worse than an exception, because a caller would silently merge
   *  onto the wrong base and destroy the other writer's data with no error
   *  anywhere. Instead the original ApiError is rethrown so the failure is
   *  visible.
   */
  async commitContext(id: string, expectedVersion: number, bytes: number, sha256: string): Promise<ContextDTO> {
    try {
      return await this.call<ContextDTO>("POST", `/v1/contexts/${encodeURIComponent(id)}/commit`, {
        expected_version: expectedVersion, bytes, sha256,
      });
    } catch (e) {
      if (e instanceof ApiError && e.status === 409) {
        const cv = e.details.current_version;
        if (typeof cv !== "number" || !Number.isFinite(cv)) throw e;
        throw new VersionConflict(cv);
      }
      throw e;
    }
  }

  // recipientInstallation is the recipient's INSTALLATION id, not a session id
  // — envelopes bind to installation (see rework-plan.md Task R2). An older
  // brief called this field recipient_session; that name is stale and the
  // server no longer recognizes it.
  addContextMember(id: string, githubUserID: GitHubUserId, role: string, recipientInstallation: InstallationId, sealedKey: string): Promise<unknown> {
    return this.call("POST", `/v1/contexts/${encodeURIComponent(id)}/members`, {
      github_user_id: githubUserID, role, recipient_installation: recipientInstallation, sealed_key: sealedKey,
    });
  }

  removeContextMember(id: string, githubUserID: GitHubUserId): Promise<ContextDTO> {
    return this.call("DELETE", `/v1/contexts/${encodeURIComponent(id)}/members/${encodeURIComponent(githubUserID)}`);
  }

  /** Authorisations the caller could answer, across every context they belong
   *  to. Empty for a caller who holds no key anywhere — see PendingKeyDTO. */
  pendingContextKeys(): Promise<PendingKeyDTO[]> {
    return this.call("GET", "/v1/contexts/pending");
  }

  /** Upload one or more sealed-key envelopes for a context's CURRENT epoch.
   *  Used both by the owner re-keying after a revoke and by any other
   *  keyholder answering a pending authorisation (piggyback answering). The
   *  server refuses to overwrite a slot that already has an envelope, so
   *  callers must only target empty slots (see rework-plan.md Task R4). */
  uploadContextKeys(id: string, envelopes: KeyEnvelope[]): Promise<unknown> {
    return this.call("POST", `/v1/contexts/${encodeURIComponent(id)}/keys`, { envelopes });
  }
}
