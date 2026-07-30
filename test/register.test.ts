import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { createServer, Server } from "node:http";
import { mkdtempSync, rmSync, existsSync, readFileSync, readdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, sep } from "node:path";
import { run } from "../src/cli.js";
import { defaultHome } from "../src/session.js";

// --- defaultHome + profile resolution (unit) ---
describe("defaultHome + profiles", () => {
  const savedHome = process.env.AGENTMSG_HOME;
  const savedProfile = process.env.AGENTMSG_PROFILE;
  const savedAgent = process.env.CLAUDE_CODE_SESSION_ID;
  beforeEach(() => {
    delete process.env.CLAUDE_CODE_SESSION_ID;
  });
  afterEach(() => {
    process.env.AGENTMSG_HOME = savedHome;
    if (savedProfile === undefined) delete process.env.AGENTMSG_PROFILE;
    else process.env.AGENTMSG_PROFILE = savedProfile;
    if (savedAgent === undefined) delete process.env.CLAUDE_CODE_SESSION_ID;
    else process.env.CLAUDE_CODE_SESSION_ID = savedAgent;
  });

  it("returns the base home when no profile and no agent session are set", () => {
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

  // Two agent sessions started in the SAME directory must not share one
  // identity: they would report the same address card, and — worse — poll one
  // inbox, so `receive --ack` in one session consumes the other's messages.
  // With no explicit profile we derive one from the agent session id.
  it("derives a distinct home per agent session id", () => {
    const baseHome = join(tmpdir(), "base");
    process.env.AGENTMSG_HOME = baseHome;
    delete process.env.AGENTMSG_PROFILE;

    process.env.CLAUDE_CODE_SESSION_ID = "f26c7ee3-ff65-4ab8-9d5c-f8ade22418b0";
    const a = defaultHome();
    process.env.CLAUDE_CODE_SESSION_ID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
    const b = defaultHome();

    expect(a).not.toBe(b);
    expect(a).not.toBe(baseHome);
    expect(a.startsWith(baseHome + sep)).toBe(true);
  });

  it("is stable for the same agent session id (survives repeated calls)", () => {
    process.env.AGENTMSG_HOME = join(tmpdir(), "base");
    delete process.env.AGENTMSG_PROFILE;
    process.env.CLAUDE_CODE_SESSION_ID = "f26c7ee3-ff65-4ab8-9d5c-f8ade22418b0";
    expect(defaultHome()).toBe(defaultHome());
  });

  it("an auto-derived profile is always a safe path segment", () => {
    const baseHome = join(tmpdir(), "base");
    process.env.AGENTMSG_HOME = baseHome;
    delete process.env.AGENTMSG_PROFILE;
    // Even a hostile session id must not escape the base home.
    process.env.CLAUDE_CODE_SESSION_ID = "../../etc/passwd";
    const h = defaultHome();
    expect(h.startsWith(baseHome + sep)).toBe(true);
    expect(h).not.toContain("..");
  });

  it("an explicit profile still wins over the agent session id", () => {
    const baseHome = join(tmpdir(), "base");
    process.env.AGENTMSG_HOME = baseHome;
    delete process.env.AGENTMSG_PROFILE;
    process.env.CLAUDE_CODE_SESSION_ID = "f26c7ee3-ff65-4ab8-9d5c-f8ade22418b0";
    expect(defaultHome("work")).toBe(join(baseHome, "work"));
  });

  it("AGENTMSG_PROFILE still wins over the agent session id", () => {
    process.env.AGENTMSG_HOME = "/tmp/base";
    process.env.AGENTMSG_PROFILE = "dev";
    process.env.CLAUDE_CODE_SESSION_ID = "f26c7ee3-ff65-4ab8-9d5c-f8ade22418b0";
    expect(defaultHome()).toBe(join("/tmp/base", "dev"));
  });

  // Escape hatch: a human who wants the one shared machine identity back.
  it("AGENTMSG_PROFILE=. opts back into the shared base home", () => {
    process.env.AGENTMSG_HOME = "/tmp/base";
    process.env.AGENTMSG_PROFILE = ".";
    process.env.CLAUDE_CODE_SESSION_ID = "f26c7ee3-ff65-4ab8-9d5c-f8ade22418b0";
    expect(defaultHome()).toBe("/tmp/base");
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
  it("reuses a valid registration in the same home and preserves the first session", async () => {
    expect(await cli("register", "--dev-user", "99", "--allow-insecure-http")).toBe(0);
    const first = JSON.parse(readFileSync(join(home, "session.json"), "utf8"));

    const code = await cli("register", "--dev-user", "99", "--allow-insecure-http");
    expect(code).toBe(0);

    const after = JSON.parse(readFileSync(join(home, "session.json"), "utf8"));
    expect(after.sessionId).toBe(first.sessionId); // session untouched
    expect(after.privateKey).toBe(first.privateKey); // keys preserved
  });

  // Windows runners can take several seconds to generate the replacement
  // Ed25519 keypair under load; this test is about overwrite semantics, not a
  // five-second performance budget.
  it("--force intentionally replaces the existing session", async () => {
    expect(await cli("register", "--dev-user", "99", "--allow-insecure-http")).toBe(0);
    const first = JSON.parse(readFileSync(join(home, "session.json"), "utf8"));

    expect(await cli("register", "--dev-user", "99", "--allow-insecure-http", "--force")).toBe(0);
    const after = JSON.parse(readFileSync(join(home, "session.json"), "utf8"));
    expect(after.sessionId).not.toBe(first.sessionId); // replaced on purpose
  }, 15_000);

  // The reported bug, end to end: two agent sessions started in the SAME
  // directory used to land on one session.json — same card, one shared inbox.
  it("two agent sessions in one directory get independent identities", async () => {
    process.env.CLAUDE_CODE_SESSION_ID = "session-one";
    expect(await cli("register", "--dev-user", "99", "--allow-insecure-http")).toBe(0);
    process.env.CLAUDE_CODE_SESSION_ID = "session-two";
    expect(await cli("register", "--dev-user", "99", "--allow-insecure-http")).toBe(0);
    delete process.env.CLAUDE_CODE_SESSION_ID;

    // Neither wrote to the shared home, and the two cards differ.
    expect(existsSync(join(home, "session.json"))).toBe(false);
    const homes = readdirSync(home).filter((d) => d.startsWith("s-"));
    expect(homes).toHaveLength(2);
    const [a, b] = homes.map((d) => JSON.parse(readFileSync(join(home, d, "session.json"), "utf8")));
    expect(a.sessionId).not.toBe(b.sessionId);
    expect(a.publicKey).not.toBe(b.publicKey);
  });

  // With one card per agent session, `whoami` must say WHICH home it read, so a
  // human looking at two sessions' cards can tell them apart.
  it("whoami reports the home the card came from", async () => {
    process.env.CLAUDE_CODE_SESSION_ID = "session-one";
    expect(await cli("register", "--dev-user", "99", "--allow-insecure-http")).toBe(0);

    const outs: string[] = [];
    const spy = vi.spyOn(process.stdout, "write").mockImplementation((c: any) => (outs.push(String(c)), true));
    await cli("whoami");
    spy.mockRestore();
    delete process.env.CLAUDE_CODE_SESSION_ID;

    const card = JSON.parse(outs.join(""));
    expect(card.home).toContain("s-");
    expect(card.home.startsWith(home)).toBe(true);
  });

  // openclaw (and any agent that spawns children without passing its session id
  // down) lands here. We can tell isolation MATTERS but cannot do it ourselves —
  // so refuse to mint an identity silently and hand the human something to paste.
  describe("inside an agent whose session id we cannot see", () => {
    function captureErr() {
      const errs: string[] = [];
      const spy = vi.spyOn(process.stderr, "write").mockImplementation((c: any) => (errs.push(String(c)), true));
      return { errs, restore: () => spy.mockRestore() };
    }

    it("refuses to register and suggests a concrete value to set", async () => {
      process.env.OPENCLAW_CLI = "1";
      const { errs, restore } = captureErr();
      const code = await cli("register", "--dev-user", "99", "--allow-insecure-http");
      restore();
      delete process.env.OPENCLAW_CLI;

      expect(code).not.toBe(0);
      expect(existsSync(join(home, "session.json"))).toBe(false); // nothing minted
      const out = errs.join("");
      expect(out).toMatch(/openclaw/i); // names what it detected
      expect(out).toMatch(/export AGENTMSG_SESSION=\S+/); // a pasteable suggestion
    });

    it("proceeds once the human sets the suggested variable", async () => {
      process.env.OPENCLAW_CLI = "1";
      process.env.AGENTMSG_SESSION = "my-openclaw-session";
      const code = await cli("register", "--dev-user", "99", "--allow-insecure-http");
      delete process.env.OPENCLAW_CLI;
      delete process.env.AGENTMSG_SESSION;

      expect(code).toBe(0);
      expect(readdirSync(home).filter((d) => d.startsWith("s-"))).toHaveLength(1);
    });

    it("an explicit --profile is also accepted as the answer", async () => {
      process.env.OPENCLAW_CLI = "1";
      const code = await cli("register", "--dev-user", "99", "--allow-insecure-http", "--profile", "mine");
      delete process.env.OPENCLAW_CLI;

      expect(code).toBe(0);
      expect(existsSync(join(home, "mine", "session.json"))).toBe(true);
    });

    it("a plain human shell is never blocked", async () => {
      expect(await cli("register", "--dev-user", "99", "--allow-insecure-http")).toBe(0);
      expect(existsSync(join(home, "session.json"))).toBe(true);
    });
  });

  // Migration: someone registered before auto-profiling existed. Their session
  // sits in the base home and is now invisible — say so, don't just claim there
  // is no session.
  it("points an agent session at a pre-existing shared session instead of just failing", async () => {
    expect(await cli("register", "--dev-user", "99", "--allow-insecure-http")).toBe(0);
    expect(existsSync(join(home, "session.json"))).toBe(true);

    const errs: string[] = [];
    const spy = vi.spyOn(process.stderr, "write").mockImplementation((c: any) => (errs.push(String(c)), true));
    const exit = vi.spyOn(process, "exit").mockImplementation(((): never => {
      throw new Error("EXIT");
    }) as any);
    process.env.CLAUDE_CODE_SESSION_ID = "a-different-session";
    try {
      await cli("whoami");
    } catch {
      /* the mocked process.exit */
    }
    delete process.env.CLAUDE_CODE_SESSION_ID;
    spy.mockRestore();
    exit.mockRestore();

    const out = errs.join("");
    expect(out).toMatch(/AGENTMSG_PROFILE=\./); // the opt-back-in escape hatch
    expect(out).toContain(home); // where the existing session actually lives
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
