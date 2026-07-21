// HTTP client for the agent-msg server API. Pure transport — no crypto here;
// the CLI layer seals/opens message bodies around these calls. Mirrors the Go
// client's endpoints and error envelope.

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

export interface SendInput {
  to: string;
  text: string;
  enc?: string;
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

  private async call<T>(method: string, path: string, body?: unknown): Promise<T> {
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
      throw e;
    }
    clearTimeout(timer);
    const raw = await readCapped(resp, MAX_RESPONSE_BYTES);
    if (!resp.ok) {
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
    return (raw ? JSON.parse(raw) : {}) as T;
  }

  register(credential: string): Promise<RegisterResponse> {
    return this.call("POST", "/v1/register", { credential });
  }

  unregister(): Promise<void> {
    return this.call("DELETE", "/v1/sessions/me");
  }

  send(input: SendInput): Promise<SendResponse> {
    const body: Record<string, unknown> = { to: input.to, text: input.text };
    if (input.enc) body.enc = input.enc;
    return this.call("POST", "/v1/messages", body);
  }

  inboxPage(after: number, limit = 0): Promise<InboxResponse> {
    let path = `/v1/inbox?after=${after}`;
    if (limit > 0) path += `&limit=${limit}`;
    return this.call("GET", path);
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

  checkout(): Promise<{ url: string }> {
    return this.call("POST", "/v1/billing/checkout");
  }

  portal(): Promise<{ url: string }> {
    return this.call("POST", "/v1/billing/portal");
  }
}
