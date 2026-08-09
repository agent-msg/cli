import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtempSync, rmSync, statSync, mkdirSync, writeFileSync, chmodSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ContextKeys } from "../src/context.js";
import { decryptSym } from "../src/crypto.js";

let home: string;
beforeEach(() => (home = mkdtempSync(join(tmpdir(), "amsg-ctx-"))));
afterEach(() => rmSync(home, { recursive: true, force: true }));

import { createServer, Server } from "node:http";
import { vi } from "vitest";
import { run } from "../src/cli.js";

let server: Server, base: string;
let ctxVersion = 0;
let lastNameEnc = "";

beforeEach(async () => {
  ctxVersion = 0;
  lastNameEnc = "";
  server = createServer((req, res) => {
    let b = "";
    req.on("data", (c) => (b += c));
    req.on("end", () => {
      // The /upload PUT carries binary ciphertext, not JSON — parsing it
      // unconditionally would crash this handler and hang the request.
      let body: any = {};
      try {
        body = b ? JSON.parse(b) : {};
      } catch {
        body = {};
      }
      res.setHeader("Content-Type", "application/json");
      if (req.url === "/v1/register") {
        return res.end(JSON.stringify({ session_id: "s1", token: "t1", github_login: "u", github_user_id: "1" }));
      }
      if (req.url === "/v1/contexts" && req.method === "POST") {
        lastNameEnc = String(body.name_enc ?? "");
        return res.end(JSON.stringify({ id: "c1", name_enc: body.name_enc, owner_uid: "1", epoch: 1, version: 0, bytes: 0, updated_at: "", role: "owner" }));
      }
      if (req.url === "/v1/contexts/c1" && req.method === "PUT") {
        return res.end(JSON.stringify({ upload_url: base + "/upload", blob_key: "k" }));
      }
      if (req.url === "/upload") return res.end("{}");
      if (req.url === "/v1/contexts/c1/commit") {
        if (body.expected_version !== ctxVersion) {
          res.statusCode = 409;
          return res.end(JSON.stringify({ error: "version_conflict", current_version: ctxVersion }));
        }
        ctxVersion++;
        return res.end(JSON.stringify({ id: "c1", name_enc: "", owner_uid: "1", epoch: 1, version: ctxVersion, bytes: 0, updated_at: "", role: "owner" }));
      }
      res.end("{}");
    });
  });
  await new Promise<void>((r) => server.listen(0, r));
  const a = server.address();
  base = `http://127.0.0.1:${typeof a === "object" && a ? a.port : 0}`;
});
afterEach(() => new Promise<void>((r) => server.close(() => r())));

async function cli(...argv: string[]) {
  process.env.AGENTMSG_HOME = home;
  process.env.AGENTMSG_SERVER = base;
  delete process.env.AGENTMSG_PROFILE;
  const code = await run(argv);
  delete process.env.AGENTMSG_HOME;
  delete process.env.AGENTMSG_SERVER;
  return code;
}

describe("agentmsg context", () => {
  it("creates a context and saves its key locally", async () => {
    expect(await cli("register", "--dev-user", "9", "--allow-insecure-http")).toBe(0);
    const out: string[] = [];
    const spy = vi.spyOn(process.stdout, "write").mockImplementation((c: any) => (out.push(String(c)), true));
    const code = await cli("context", "create", "--name", "team notes");
    spy.mockRestore();

    expect(code).toBe(0);
    const savedKey = new ContextKeys(home).get("c1");
    expect(savedKey).toBeTruthy(); // key stored for later reads
    expect(out.join("")).not.toContain("team notes"); // the CLI doesn't print it

    // The actual product promise: the server must never receive the plaintext
    // name. Proving stdout is clean isn't enough — prove what left the machine
    // was neither the plaintext nor some other garbage, but genuinely the
    // ciphertext of "team notes" under the key that got saved locally.
    expect(lastNameEnc).not.toBe("team notes");
    expect(lastNameEnc).not.toContain("team notes");
    expect(await decryptSym(lastNameEnc, savedKey!)).toBe("team notes");
  });

  // Conflicts are the normal path, so the CLI must surface everything the
  // agent needs to merge instead of just failing.
  it("reports a conflict with the data needed to merge", async () => {
    expect(await cli("register", "--dev-user", "9", "--allow-insecure-http")).toBe(0);
    await cli("context", "create", "--name", "n");
    ctxVersion = 5; // someone else moved it while we were editing

    const errs: string[] = [];
    const spy = vi.spyOn(process.stderr, "write").mockImplementation((c: any) => (errs.push(String(c)), true));
    const code = await cli("context", "set", "--id", "c1", "--text", "mine", "--expect", "0");
    spy.mockRestore();

    expect(code).not.toBe(0);
    const msg = errs.join("");
    expect(msg).toMatch(/version_conflict|conflict/i);
    expect(msg).toContain("5");           // the version we must rebase onto
    expect(msg).toMatch(/context get/);   // tells the agent how to fetch it
  });
});

describe("ContextKeys", () => {
  it("round-trips a key", () => {
    const k = new ContextKeys(home);
    k.save("ctx1", "base64key");
    expect(k.get("ctx1")).toBe("base64key");
  });

  it("returns undefined for an unknown context", () => {
    expect(new ContextKeys(home).get("nope")).toBeUndefined();
  });

  it("persists across instances", () => {
    new ContextKeys(home).save("ctx1", "key1");
    expect(new ContextKeys(home).get("ctx1")).toBe("key1");
  });

  // The file holds decryption keys for shared documents; group- or
  // world-readable would expose every context on a shared machine.
  it("stores keys with owner-only permissions", () => {
    const k = new ContextKeys(home);
    k.save("ctx1", "key1");
    expect(statSync(join(home, "contexts.json")).mode & 0o077).toBe(0);
  });

  it("lists saved context ids", () => {
    const k = new ContextKeys(home);
    k.save("a", "1");
    k.save("b", "2");
    expect(k.list().sort()).toEqual(["a", "b"]);
  });

  // A file that is valid JSON but the wrong shape must be treated the same
  // as a corrupt/missing one, not crash the caller.
  it("treats a JSON `null` file as empty", () => {
    mkdirSync(home, { recursive: true });
    writeFileSync(join(home, "contexts.json"), "null");
    expect(new ContextKeys(home).get("ctx1")).toBeUndefined();
  });

  it("treats a JSON `{}` file as empty and can still save into it", () => {
    mkdirSync(home, { recursive: true });
    writeFileSync(join(home, "contexts.json"), "{}");
    const k = new ContextKeys(home);
    expect(() => k.save("ctx1", "key1")).not.toThrow();
    expect(k.get("ctx1")).toBe("key1");
  });

  // Enforces the mode even when contexts.json already existed with looser
  // permissions before save() ran — writeFileSync/atomicWritePrivate must not
  // silently inherit stale permissions from a pre-existing file.
  it("tightens permissions on a pre-existing, loosely-permissioned file", () => {
    mkdirSync(home, { recursive: true });
    const file = join(home, "contexts.json");
    writeFileSync(file, JSON.stringify({ keys: {} }));
    chmodSync(file, 0o644);
    const k = new ContextKeys(home);
    k.save("ctx1", "key1");
    expect(statSync(file).mode & 0o077).toBe(0);
  });
});
