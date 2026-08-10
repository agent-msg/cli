// R7: shared-context keys are sealed to the installation identity, which is
// supposed to be stable across agent sessions on one machine. But isolation
// (defaultHome()) derives a per-session profile home, and InstallationStore
// used to be constructed with THAT home — so two sessions on one machine
// silently got two different "machine" identities, and a context key saved
// under one session could never be opened by the other. This file proves the
// bug is fixed: installation identity (and the context keys sealed to it)
// must live in the base home, while session state stays isolated per session.
import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { createServer, Server } from "node:http";
import { closeServer } from "./setup.js";
import { mkdtempSync, rmSync, existsSync, mkdirSync, writeFileSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { run } from "../src/cli.js";
import { defaultHome, baseHome } from "../src/session.js";
import { InstallationStore } from "../src/installation.js";
import { ContextKeys } from "../src/context.js";

let base: string; // AGENTMSG_HOME (the machine's base home for this test)
let server: Server, serverUrl: string;
let ctxEpoch = 1;
let ctxVersion = 0;
let lastNameEnc = "";
let ctxSealedKey = "";
let ctxDownloadContent = "";
let ctxHasContent = false;
let pendingList: unknown[] = [];
let uploadedEnvelopes: { context_id: string; envelopes: unknown[] }[] = [];

const savedEnv: Record<string, string | undefined> = {};
const TOUCHED = ["AGENTMSG_HOME", "AGENTMSG_SERVER", "AGENTMSG_PROFILE", "CLAUDE_CODE_SESSION_ID", "AGENTMSG_DISABLE_KEYCHAIN", "AGENTMSG_TEST_SKIP_WINDOWS_ACL"];

beforeEach(async () => {
  for (const k of TOUCHED) savedEnv[k] = process.env[k];
  base = mkdtempSync(join(tmpdir(), "amsg-shared-install-"));
  process.env.AGENTMSG_DISABLE_KEYCHAIN = "1";
  process.env.AGENTMSG_TEST_SKIP_WINDOWS_ACL = "1";
  delete process.env.AGENTMSG_PROFILE;

  ctxEpoch = 1;
  ctxVersion = 0;
  lastNameEnc = "";
  ctxSealedKey = "";
  ctxDownloadContent = "";
  ctxHasContent = false;
  pendingList = [];
  uploadedEnvelopes = [];

  server = createServer((req, res) => {
    let b = "";
    req.on("data", (c) => (b += c));
    req.on("end", () => {
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
      if (req.url === "/v1/whoami/card" && req.method === "GET") {
        return res.end(JSON.stringify({
          version: 1, service: "agentmsg", identity_type: "github", principal_id: "1",
          installation_id: "install-self", session_id: "s1", verified: true,
          public_key: "", signature: "", github_user_id: "1", github_login: "u",
        }));
      }
      if (req.url === "/v1/contexts" && req.method === "POST") {
        lastNameEnc = String(body.name_enc ?? "");
        ctxEpoch = 1;
        return res.end(JSON.stringify({ id: "c1", name_enc: body.name_enc, owner_uid: "1", epoch: ctxEpoch, version: 0, bytes: 0, updated_at: "", role: "owner" }));
      }
      if (req.url === "/v1/contexts" && req.method === "GET") {
        return res.end(JSON.stringify([{ id: "c1", name_enc: lastNameEnc, owner_uid: "1", epoch: ctxEpoch, version: ctxVersion, bytes: ctxHasContent ? 1 : 0, updated_at: "", role: "owner" }]));
      }
      if (req.url === "/v1/contexts/pending" && req.method === "GET") {
        return res.end(JSON.stringify(pendingList));
      }
      if (req.url === "/v1/contexts/c1/keys" && req.method === "POST") {
        uploadedEnvelopes.push({ context_id: "c1", envelopes: body.envelopes || [] });
        return res.end(JSON.stringify({ status: "stored" }));
      }
      if (req.url === "/v1/contexts/c1" && req.method === "GET") {
        return res.end(JSON.stringify({
          id: "c1", name_enc: "", owner_uid: "1", epoch: ctxEpoch, version: ctxVersion,
          bytes: ctxHasContent ? 1 : 0, updated_at: "", role: "owner",
          download_url: ctxHasContent ? serverUrl + "/download-content" : undefined,
          sealed_key: ctxSealedKey || undefined,
        }));
      }
      if (req.url === "/download-content" && req.method === "GET") {
        return res.end(ctxDownloadContent);
      }
      if (req.url === "/v1/contexts/c1" && req.method === "PUT") {
        return res.end(JSON.stringify({ upload_url: serverUrl + "/upload", blob_key: "k" }));
      }
      if (req.url === "/upload") {
        ctxDownloadContent = b;
        ctxHasContent = true;
        return res.end("{}");
      }
      if (req.url === "/v1/contexts/c1/commit") {
        if (body.expected_version !== ctxVersion) {
          res.statusCode = 409;
          return res.end(JSON.stringify({ error: "version_conflict", current_version: ctxVersion }));
        }
        ctxVersion++;
        return res.end(JSON.stringify({ id: "c1", name_enc: "", owner_uid: "1", epoch: ctxEpoch, version: ctxVersion, bytes: 0, updated_at: "", role: "owner" }));
      }
      res.end("{}");
    });
  });
  await new Promise<void>((r) => server.listen(0, r));
  const a = server.address();
  serverUrl = `http://127.0.0.1:${typeof a === "object" && a ? a.port : 0}`;
});

afterEach(async () => {
  await closeServer(server);
  rmSync(base, { recursive: true, force: true });
  for (const k of TOUCHED) {
    if (savedEnv[k] === undefined) delete process.env[k];
    else process.env[k] = savedEnv[k];
  }
});

/** Runs the CLI as if inside the given Claude Code session id, against the
 *  shared base home for this test. */
async function cliAsSession(sessionId: string, ...argv: string[]) {
  process.env.AGENTMSG_HOME = base;
  process.env.AGENTMSG_SERVER = serverUrl;
  process.env.CLAUDE_CODE_SESSION_ID = sessionId;
  delete process.env.AGENTMSG_PROFILE;
  const code = await run(argv);
  delete process.env.AGENTMSG_HOME;
  delete process.env.AGENTMSG_SERVER;
  delete process.env.CLAUDE_CODE_SESSION_ID;
  return code;
}

describe("installation identity is shared across agent sessions on one machine", () => {
  it("two different agent session ids derive the SAME installation public key, while session homes remain distinct", () => {
    process.env.AGENTMSG_HOME = base;
    process.env.CLAUDE_CODE_SESSION_ID = "session-AAAA";
    const homeA = defaultHome();
    process.env.CLAUDE_CODE_SESSION_ID = "session-BBBB";
    const homeB = defaultHome();
    expect(homeA).not.toBe(homeB); // session isolation must still hold

    const keyA = new InstallationStore(baseHome(), { legacyHome: homeA }).loadOrCreate();
    const keyB = new InstallationStore(baseHome(), { legacyHome: homeB }).loadOrCreate();
    expect(keyA.publicKey).toBe(keyB.publicKey); // THE bug: must now match
    delete process.env.CLAUDE_CODE_SESSION_ID;
  });

  it("a context key saved under one session id is readable from another session id on the same machine", async () => {
    expect(await cliAsSession("session-AAAA", "register", "--dev-user", "9", "--allow-insecure-http")).toBe(0);
    expect(await cliAsSession("session-BBBB", "register", "--dev-user", "9", "--allow-insecure-http")).toBe(0);

    const outA: string[] = [];
    const spyA = vi.spyOn(process.stdout, "write").mockImplementation((c: any) => (outA.push(String(c)), true));
    const codeCreate = await cliAsSession("session-AAAA", "context", "create", "--name", "team notes");
    spyA.mockRestore();
    expect(codeCreate).toBe(0);

    const outB: string[] = [];
    const spyB = vi.spyOn(process.stdout, "write").mockImplementation((c: any) => (outB.push(String(c)), true));
    const codeGet = await cliAsSession("session-BBBB", "context", "get", "--id", "c1");
    spyB.mockRestore();

    expect(codeGet).toBe(0); // must succeed: session B can decrypt what session A wrote
    expect(JSON.parse(outB.join(""))).toMatchObject({ context_id: "c1" });
  });
});

describe("session state stays isolated per session id (must not regress)", () => {
  it("session.json differs between two agent session ids", async () => {
    expect(await cliAsSession("session-AAAA", "register", "--dev-user", "9", "--allow-insecure-http")).toBe(0);
    expect(await cliAsSession("session-BBBB", "register", "--dev-user", "9", "--allow-insecure-http")).toBe(0);

    process.env.AGENTMSG_HOME = base;
    process.env.CLAUDE_CODE_SESSION_ID = "session-AAAA";
    const homeA = defaultHome();
    process.env.CLAUDE_CODE_SESSION_ID = "session-BBBB";
    const homeB = defaultHome();
    delete process.env.CLAUDE_CODE_SESSION_ID;
    delete process.env.AGENTMSG_HOME;

    expect(homeA).not.toBe(homeB);
    expect(existsSync(join(homeA, "session.json"))).toBe(true);
    expect(existsSync(join(homeB, "session.json"))).toBe(true);
  });
});

describe("InstallationStore migrates a pre-existing profile-scoped identity into the base home", () => {
  it("promotes an existing legacy key rather than minting a new identity, so context keys sealed to it stay valid", () => {
    const legacyHome = join(base, "s-legacyprofile");
    const legacyKey = new InstallationStore(legacyHome).loadOrCreate();
    expect(existsSync(join(base, "installation.key"))).toBe(false); // precondition: nothing in base home yet

    const migrated = new InstallationStore(base, { legacyHome }).loadOrCreate();
    expect(migrated.publicKey).toBe(legacyKey.publicKey);
    expect(migrated.seed.equals(legacyKey.seed)).toBe(true);
    expect(existsSync(join(base, "installation.key"))).toBe(true);
    if (process.platform !== "win32") {
      const { statSync } = require("node:fs");
      expect(statSync(join(base, "installation.key")).mode & 0o777).toBe(0o600);
    }
  });

  it("does not overwrite an installation identity that already exists in the base home", () => {
    const baseKey = new InstallationStore(base).loadOrCreate();
    const legacyHome = join(base, "s-somethingelse");
    new InstallationStore(legacyHome).loadOrCreate(); // a different identity, never promoted

    const result = new InstallationStore(base, { legacyHome }).loadOrCreate();
    expect(result.publicKey).toBe(baseKey.publicKey);
  });
});
