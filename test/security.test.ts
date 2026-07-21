import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { createServer, Server } from "node:http";
import { mkdtempSync, rmSync, writeFileSync, chmodSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { run } from "../src/cli.js";
import { Contacts, fingerprint } from "../src/contacts.js";
import { generateKeypair } from "../src/crypto.js";

// Stub server that records sends, so "no network send" assertions are testable.
let server: Server, base: string;
const sends: any[] = [];
beforeEach(async () => {
  sends.length = 0;
  server = createServer((req, res) => {
    let b = "";
    req.on("data", (c) => (b += c));
    req.on("end", () => {
      if (req.url === "/v1/register") return res.end(JSON.stringify({ session_id: "s", token: "t", github_login: "u", github_user_id: "1" }));
      if (req.url === "/v1/messages") { sends.push(JSON.parse(b)); return res.end(JSON.stringify({ msg_id: "m", seq: 1 })); }
      res.end("{}");
    });
  });
  await new Promise<void>((r) => server.listen(0, r));
  const a = server.address();
  base = `http://127.0.0.1:${typeof a === "object" && a ? a.port : 0}`;
});
afterEach(() => new Promise<void>((r) => server.close(() => r())));

let home: string;
async function cli(...argv: string[]) {
  process.env.AGENTMSG_HOME = home;
  process.env.AGENTMSG_SERVER = base;
  const code = await run(argv);
  delete process.env.AGENTMSG_HOME;
  delete process.env.AGENTMSG_SERVER;
  return code;
}
beforeEach(() => (home = mkdtempSync(join(tmpdir(), "amsg-sec-"))));
afterEach(() => rmSync(home, { recursive: true, force: true }));

describe("SEC-04: fail closed on missing public key", () => {
  it("refuses to send and makes NO network call when the recipient has no key", async () => {
    await cli("register", "--dev-user", "99", "--allow-insecure-http");
    const code = await cli("send", "--to", "unknown_sid", "--text", "secret");
    expect(code).toBe(1);
    expect(sends).toHaveLength(0); // nothing left the machine
  });

  it("sends plaintext only with the explicit --plaintext --i-understand-the-risk", async () => {
    await cli("register", "--dev-user", "99", "--allow-insecure-http");
    const code = await cli("send", "--to", "unknown_sid", "--text", "hi", "--plaintext", "--i-understand-the-risk");
    expect(code).toBe(0);
    expect(sends).toHaveLength(1);
    expect(sends[0].enc).toBeUndefined();
  });

  it("a corrupt contacts file blocks the send instead of falling back to plaintext", async () => {
    await cli("register", "--dev-user", "99", "--allow-insecure-http");
    writeFileSync(join(home, "contacts.json"), "{corrupt");
    const code = await cli("send", "--to", "carol", "--text", "secret");
    expect(code).toBe(1);
    expect(sends).toHaveLength(0);
  });
});

describe("SEC-05: public-key fingerprint + trust-on-first-use", () => {
  it("fingerprint is stable and formatted for out-of-band comparison", () => {
    const fp = fingerprint("GXbeyR+fLnJVeF8ENMzZzHA/1CrXOQXxdOeQ8svqWWM=");
    expect(fp).toMatch(/^[0-9a-f]{4}(-[0-9a-f]{4}){3}$/);
    expect(fingerprint("GXbeyR+fLnJVeF8ENMzZzHA/1CrXOQXxdOeQ8svqWWM=")).toBe(fp); // deterministic
  });

  it("refuses to overwrite a contact's key with a different one unless forced", async () => {
    const c = new Contacts(home);
    const k1 = await generateKeypair();
    const k2 = await generateKeypair();
    c.add("carol", { sessionId: "s", publicKey: k1.publicKey, githubUserId: "1" });
    expect(() => c.add("carol", { sessionId: "s", publicKey: k2.publicKey, githubUserId: "1" })).toThrow(/different public key/i);
    // Re-saving the SAME key is idempotent (no throw).
    expect(() => c.add("carol", { sessionId: "s", publicKey: k1.publicKey, githubUserId: "1" })).not.toThrow();
    // With force, the key is replaced.
    c.add("carol", { sessionId: "s", publicKey: k2.publicKey, githubUserId: "1" }, true);
    expect(c.resolve("carol")?.publicKey).toBe(k2.publicKey);
  });

  it("a corrupt contacts file throws rather than reading as empty", () => {
    writeFileSync(join(home, "contacts.json"), "{not json");
    expect(() => new Contacts(home).list()).toThrow(/corrupt/i);
  });
});
