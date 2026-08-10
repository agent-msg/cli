// R4b/R7 follow-up: the compact address card, `whoami`, and `card` output
// must all carry the installation id — the value `context share` needs to
// address envelopes correctly (see contacts.test.ts and context.test.ts for
// the sharing-side assertions). Without it round-tripping through the card,
// there is never a correct value for a fresh contact to record.
import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { run } from "../src/cli.js";
import { SessionStore, Session } from "../src/session.js";

let home: string;
beforeEach(() => (home = mkdtempSync(join(tmpdir(), "amsg-card-"))));
afterEach(() => rmSync(home, { recursive: true, force: true }));

function baseSession(): Session {
  return {
    serverUrl: "http://example.invalid",
    sessionId: "sess-123",
    token: "tok",
    githubLogin: "u",
    githubUserId: "1",
    publicKey: "PK",
    privateKey: "SK",
    installationId: "install-xyz",
    installationBoxKey: "IBK",
  };
}

async function cli(...argv: string[]) {
  process.env.AGENTMSG_HOME = home;
  const out: string[] = [];
  const spy = vi.spyOn(process.stdout, "write").mockImplementation((c: any) => (out.push(String(c)), true));
  const code = await run(argv);
  spy.mockRestore();
  delete process.env.AGENTMSG_HOME;
  return { code, out: out.join("") };
}

describe("address card carries installation id", () => {
  it("whoami includes installation_id, distinct from session_id", async () => {
    new SessionStore(home).save(baseSession());
    const { code, out } = await cli("whoami");
    expect(code).toBe(0);
    const parsed = JSON.parse(out);
    expect(parsed.installation_id).toBe("install-xyz");
    expect(parsed.installation_id).not.toBe(parsed.session_id);
  });

  it("card emits a compact card that decodes to include the installation id", async () => {
    new SessionStore(home).save(baseSession());
    const { code, out } = await cli("card");
    expect(code).toBe(0);
    const parsed = JSON.parse(out);
    expect(parsed.card).toMatch(/^am1:/);
    const decoded = JSON.parse(Buffer.from(parsed.card.slice(4), "base64url").toString("utf8"));
    expect(decoded.iid).toBe("install-xyz");
    expect(decoded.sid).toBe("sess-123");
    expect(decoded.iid).not.toBe(decoded.sid);
  });

  it("contact add --card round-trips the installation id into the saved contact", async () => {
    new SessionStore(home).save(baseSession());
    const { out: cardOut } = await cli("card");
    const card = JSON.parse(cardOut).card as string;

    const other = mkdtempSync(join(tmpdir(), "amsg-card-other-"));
    process.env.AGENTMSG_HOME = other;
    const code = await run(["contact", "add", "friend", "--card", card]);
    expect(code).toBe(0);
    const { Contacts } = await import("../src/contacts.js");
    const saved = new Contacts(other).resolve("friend")!;
    expect(saved.installationId).toBe("install-xyz");
    expect(saved.installationId).not.toBe(saved.sessionId);
    delete process.env.AGENTMSG_HOME;
    rmSync(other, { recursive: true, force: true });
  });

  it("contact add --installation-id flag saves it on the contact", async () => {
    process.env.AGENTMSG_HOME = home;
    const result = await run([
      "contact", "add", "bob",
      "--sid", "s-bob", "--pubkey", "PKb", "--user", "9",
      "--installation-id", "install-bob",
    ]);
    delete process.env.AGENTMSG_HOME;
    expect(result).toBe(0);
    const { Contacts } = await import("../src/contacts.js");
    const saved = new Contacts(home).resolve("bob")!;
    expect(saved.installationId).toBe("install-bob");
  });
});
