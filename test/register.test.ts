import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { createServer, Server } from "node:http";
import { mkdtempSync, rmSync, existsSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { run } from "../src/cli.js";
import { defaultHome } from "../src/session.js";

// --- defaultHome + profile resolution (unit) ---
describe("defaultHome + profiles", () => {
  const savedHome = process.env.AGENTMSG_HOME;
  const savedProfile = process.env.AGENTMSG_PROFILE;
  afterEach(() => {
    process.env.AGENTMSG_HOME = savedHome;
    if (savedProfile === undefined) delete process.env.AGENTMSG_PROFILE;
    else process.env.AGENTMSG_PROFILE = savedProfile;
  });

  it("returns the base home when no profile is set", () => {
    process.env.AGENTMSG_HOME = "/tmp/base";
    delete process.env.AGENTMSG_PROFILE;
    expect(defaultHome()).toBe("/tmp/base");
  });

  it("appends AGENTMSG_PROFILE as a subdirectory", () => {
    process.env.AGENTMSG_HOME = "/tmp/base";
    process.env.AGENTMSG_PROFILE = "dev";
    expect(defaultHome()).toBe(join("/tmp/base", "dev"));
  });

  it("an explicit profile argument wins over the env var", () => {
    process.env.AGENTMSG_HOME = "/tmp/base";
    process.env.AGENTMSG_PROFILE = "dev";
    expect(defaultHome("work")).toBe(join("/tmp/base", "work"));
  });

  it("rejects a profile containing path separators (no traversal)", () => {
    process.env.AGENTMSG_HOME = "/tmp/base";
    expect(() => defaultHome("../evil")).toThrow();
    expect(() => defaultHome("a/b")).toThrow();
  });
});

// --- register never silently clobbers an existing session (integration) ---
let server: Server, base: string, regCount: number;
beforeEach(async () => {
  regCount = 0;
  server = createServer((req, res) => {
    let b = "";
    req.on("data", (c) => (b += c));
    req.on("end", () => {
      if (req.url === "/v1/register") {
        regCount++;
        return res.end(JSON.stringify({ session_id: "s" + regCount, token: "t" + regCount, github_login: "u", github_user_id: "1" }));
      }
      res.end("{}");
    });
  });
  await new Promise<void>((r) => server.listen(0, r));
  const a = server.address();
  base = `http://127.0.0.1:${typeof a === "object" && a ? a.port : 0}`;
});
afterEach(() => new Promise<void>((r) => server.close(() => r())));

let home: string;
beforeEach(() => (home = mkdtempSync(join(tmpdir(), "amsg-reg-"))));
afterEach(() => rmSync(home, { recursive: true, force: true }));

async function cli(...argv: string[]) {
  process.env.AGENTMSG_HOME = home;
  process.env.AGENTMSG_SERVER = base;
  delete process.env.AGENTMSG_PROFILE;
  const code = await run(argv);
  delete process.env.AGENTMSG_HOME;
  delete process.env.AGENTMSG_SERVER;
  return code;
}

describe("register: no silent overwrite (the same-machine clobber bug)", () => {
  it("refuses a second register in the same home and preserves the first session", async () => {
    expect(await cli("register", "--dev-user", "99", "--allow-insecure-http")).toBe(0);
    const first = JSON.parse(readFileSync(join(home, "session.json"), "utf8"));

    const code = await cli("register", "--dev-user", "99", "--allow-insecure-http");
    expect(code).not.toBe(0); // must refuse, not overwrite

    const after = JSON.parse(readFileSync(join(home, "session.json"), "utf8"));
    expect(after.sessionId).toBe(first.sessionId); // session untouched
    expect(after.privateKey).toBe(first.privateKey); // keys preserved
  });

  it("--force intentionally replaces the existing session", async () => {
    expect(await cli("register", "--dev-user", "99", "--allow-insecure-http")).toBe(0);
    const first = JSON.parse(readFileSync(join(home, "session.json"), "utf8"));

    expect(await cli("register", "--dev-user", "99", "--allow-insecure-http", "--force")).toBe(0);
    const after = JSON.parse(readFileSync(join(home, "session.json"), "utf8"));
    expect(after.sessionId).not.toBe(first.sessionId); // replaced on purpose
  });

  it("--profile isolates sessions on one machine (no cross-clobber)", async () => {
    expect(await cli("register", "--dev-user", "99", "--allow-insecure-http", "--profile", "alice")).toBe(0);
    expect(await cli("register", "--dev-user", "99", "--allow-insecure-http", "--profile", "bob")).toBe(0);

    expect(existsSync(join(home, "alice", "session.json"))).toBe(true);
    expect(existsSync(join(home, "bob", "session.json"))).toBe(true);
    expect(existsSync(join(home, "session.json"))).toBe(false); // profiles don't touch the default home

    const a = JSON.parse(readFileSync(join(home, "alice", "session.json"), "utf8"));
    const b = JSON.parse(readFileSync(join(home, "bob", "session.json"), "utf8"));
    expect(a.sessionId).not.toBe(b.sessionId); // independent identities
  });
});
