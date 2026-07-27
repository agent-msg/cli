import { describe, it, expect, beforeAll, afterAll, vi } from "vitest";
import { createServer, Server, IncomingMessage, ServerResponse } from "node:http";
import { Client, ApiError } from "../src/client.js";

// A tiny stub server that records requests and replies from a scripted table.
interface Recorded {
  method: string;
  path: string;
  auth?: string;
  body: any;
}
let server: Server;
let base: string;
let last: Recorded;
let reply: { status: number; body: any };

beforeAll(async () => {
  server = createServer((req: IncomingMessage, res: ServerResponse) => {
    let chunks = "";
    req.on("data", (c) => (chunks += c));
    req.on("end", () => {
      last = {
        method: req.method!,
        path: req.url!,
        auth: req.headers["authorization"] as string | undefined,
        body: chunks ? JSON.parse(chunks) : undefined,
      };
      res.writeHead(reply.status, { "Content-Type": "application/json" });
      res.end(typeof reply.body === "string" ? reply.body : JSON.stringify(reply.body));
    });
  });
  await new Promise<void>((r) => server.listen(0, r));
  const addr = server.address();
  base = `http://127.0.0.1:${typeof addr === "object" && addr ? addr.port : 0}`;
});
afterAll(() => new Promise<void>((r) => server.close(() => r())));

describe("Client", () => {
  it("register posts the credential and returns the card", async () => {
    reply = { status: 200, body: { session_id: "s1", token: "t1", github_login: "alice", github_user_id: "42" } };
    const c = new Client(base);
    const r = await c.register("42:alice");
    expect(last.method).toBe("POST");
    expect(last.path).toBe("/v1/register");
    expect(last.body).toEqual({ credential: "42:alice" });
    expect(r.github_user_id).toBe("42");
  });

  it("send includes the bearer token and the enc flag when encrypted", async () => {
    reply = { status: 200, body: { msg_id: "m1", seq: 1 } };
    const c = new Client(base, "tok");
    await c.send({ to: "s1", text: "CIPHERTEXT==", enc: "box1" });
    expect(last.auth).toBe("Bearer tok");
    expect(last.body).toEqual({ to: "s1", text: "CIPHERTEXT==", enc: "box1" });
  });

  it("send omits enc for plaintext", async () => {
    reply = { status: 200, body: { msg_id: "m1", seq: 1 } };
    const c = new Client(base, "tok");
    await c.send({ to: "s1", text: "hi" });
    expect(last.body).toEqual({ to: "s1", text: "hi" });
    expect("enc" in last.body).toBe(false);
  });

  it("maps a server error envelope to ApiError with the stable code", async () => {
    reply = { status: 403, body: { error: "target_not_found", message: "not authorized to message this session" } };
    const c = new Client(base, "tok");
    await expect(c.send({ to: "nope", text: "hi" })).rejects.toMatchObject({
      status: 403,
      code: "target_not_found",
    });
    await expect(c.send({ to: "nope", text: "hi" })).rejects.toBeInstanceOf(ApiError);
  });

  it("inboxPage builds the after/limit query", async () => {
    reply = { status: 200, body: { messages: [], cursor: 0 } };
    const c = new Client(base, "tok");
    await c.inboxPage(5, 50);
    expect(last.path).toBe("/v1/inbox?after=5&limit=50");
  });

  it("setPolicy sends mode/allow/risk ack", async () => {
    reply = { status: 200, body: { status: "ok" } };
    const c = new Client(base, "tok");
    await c.setPolicy("git_user", ["42"], false);
    expect(last.method).toBe("PUT");
    expect(last.body).toEqual({ mode: "git_user", allow: ["42"], i_understand_the_risk: false });
  });

  it("retries an ambiguous registration with the exact same idempotent payload", async () => {
    const original = globalThis.fetch;
    const bodies: string[] = [];
    let calls = 0;
    globalThis.fetch = vi.fn(async (_url, init) => {
      bodies.push(String(init?.body));
      if (calls++ === 0) throw new TypeError("connection reset");
      return new Response(JSON.stringify({
        session_id: "ses_1",
        token: "tok",
        principal_id: "gst_1",
        installation_id: "ins_1",
        identity_type: "guest",
        verified: false,
        expires_at: "2099-01-01T00:00:00Z",
        address_card: {},
      }), { status: 200 });
    });
    try {
      const client = new Client(base);
      await client.guestRegistration({ challenge_id: "chl_1", idempotency_key: "same-key" });
      expect(bodies).toHaveLength(2);
      expect(bodies[1]).toBe(bodies[0]);
    } finally {
      globalThis.fetch = original;
    }
  });
});

describe("Client hardening (HARD-01)", () => {
  it("rejects a response larger than the cap via Content-Length", async () => {
    reply = { status: 200, body: "x" };
    // Force a huge declared length by overriding the handler once.
    const big = new Client(base, "tok");
    // Monkeypatch fetch for this call to return an oversized content-length.
    const orig = globalThis.fetch;
    globalThis.fetch = async () =>
      new Response("{}", { status: 200, headers: { "content-length": String(64 * 1024 * 1024) } });
    await expect(big.inboxPage(0)).rejects.toMatchObject({ code: "response_too_large" });
    globalThis.fetch = orig;
  });

  it("rejects a URL that would send credentials to a remote http origin", () => {
    expect(() => new Client("http://attacker.example", "tok")).toThrow(/loopback|https/i);
    expect(() => new Client("https://ok.example", "tok")).not.toThrow();
    expect(() => new Client("http://127.0.0.1:9", "tok")).not.toThrow(); // loopback ok
  });
});
