import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { createServer, Server } from "node:http";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { run } from "../src/cli.js";

// A fake server that records what the CLI actually sent.
let server: Server, base: string, home: string;
let seen: { path: string; auth: string; body: any } | null;
let reply: { status: number; body: any };

beforeEach(async () => {
  seen = null;
  reply = { status: 200, body: { feedback_id: "fb_abc", kind: "other", remaining_today: 9 } };
  server = createServer((req, res) => {
    let b = "";
    req.on("data", (c) => (b += c));
    req.on("end", () => {
      if (req.url === "/v1/register") {
        return res.end(JSON.stringify({ session_id: "s1", token: "t1", github_login: "u", github_user_id: "1" }));
      }
      if (req.url === "/v1/feedback") {
        seen = { path: req.url, auth: req.headers.authorization || "", body: b ? JSON.parse(b) : null };
        res.statusCode = reply.status;
        res.setHeader("Content-Type", "application/json");
        return res.end(JSON.stringify(reply.body));
      }
      res.end("{}");
    });
  });
  await new Promise<void>((r) => server.listen(0, r));
  const a = server.address();
  base = `http://127.0.0.1:${typeof a === "object" && a ? a.port : 0}`;
  home = mkdtempSync(join(tmpdir(), "amsg-fb-"));
});
afterEach(async () => {
  await new Promise<void>((r) => server.close(() => r()));
  rmSync(home, { recursive: true, force: true });
});

async function cli(...argv: string[]) {
  process.env.AGENTMSG_HOME = home;
  process.env.AGENTMSG_SERVER = base;
  delete process.env.AGENTMSG_PROFILE;
  const code = await run(argv);
  delete process.env.AGENTMSG_HOME;
  delete process.env.AGENTMSG_SERVER;
  return code;
}

async function registered() {
  expect(await cli("register", "--dev-user", "99", "--allow-insecure-http")).toBe(0);
}

function captureOut() {
  const outs: string[] = [];
  const spy = vi.spyOn(process.stdout, "write").mockImplementation((c: any) => (outs.push(String(c)), true));
  return { outs, restore: () => spy.mockRestore() };
}
function captureErr() {
  const errs: string[] = [];
  const spy = vi.spyOn(process.stderr, "write").mockImplementation((c: any) => (errs.push(String(c)), true));
  return { errs, restore: () => spy.mockRestore() };
}

describe("agentmsg feedback", () => {
  it("posts the text and reports what came back", async () => {
    await registered();
    reply.body = { feedback_id: "fb_abc", kind: "bug", remaining_today: 9 };

    const { outs, restore } = captureOut();
    const code = await cli("feedback", "--text", "receive ate my messages", "--kind", "bug");
    restore();

    expect(code).toBe(0);
    expect(seen!.body.text).toBe("receive ate my messages");
    expect(seen!.body.kind).toBe("bug");
    expect(seen!.auth).toBe("Bearer t1");

    const out = JSON.parse(outs.join(""));
    expect(out.feedback_id).toBe("fb_abc");
    expect(out.remaining_today).toBe(9);
  });

  // The whole point of --kind is server-side triage; a typo silently becoming
  // "other" would quietly mislabel the report.
  it("rejects an unknown --kind locally instead of sending it", async () => {
    await registered();
    const { restore } = captureErr();
    const code = await cli("feedback", "--text", "hi", "--kind", "complaint");
    restore();

    expect(code).not.toBe(0);
    expect(seen).toBeNull(); // never hit the network
  });

  it("omits kind entirely when not given, letting the server default it", async () => {
    await registered();
    const { restore } = captureOut();
    await cli("feedback", "--text", "nice tool");
    restore();
    expect(seen!.body.kind).toBeUndefined();
  });

  it("requires --text", async () => {
    await registered();
    const { restore } = captureErr();
    const code = await cli("feedback");
    restore();
    expect(code).toBe(2); // usage error
    expect(seen).toBeNull();
  });

  // Lets the operator reproduce a bug without asking the reporter what they ran.
  it("sends a client string identifying the CLI version and platform", async () => {
    await registered();
    const { restore } = captureOut();
    await cli("feedback", "--text", "hi");
    restore();
    expect(seen!.body.client).toMatch(/^agentmsg\/\d+\.\d+\.\d+ \S+$/);
  });

  it("needs a session", async () => {
    const { restore } = captureErr();
    const exit = vi.spyOn(process, "exit").mockImplementation(((): never => {
      throw new Error("EXIT");
    }) as any);
    try {
      await cli("feedback", "--text", "hi");
    } catch {
      /* mocked exit */
    }
    exit.mockRestore();
    restore();
    expect(seen).toBeNull();
  });

  // The daily cap is a normal outcome, not a crash — the agent should be able to
  // tell its human what happened.
  it("surfaces the daily quota error", async () => {
    await registered();
    reply = { status: 429, body: { error: "quota_exceeded", message: "usage quota exceeded" } };

    const { errs, restore } = captureErr();
    const code = await cli("feedback", "--text", "hi");
    restore();

    expect(code).toBe(1);
    expect(errs.join("")).toMatch(/quota_exceeded/);
  });
});
