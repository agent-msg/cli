import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtempSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { SessionStore } from "../src/session.js";

let home: string;
beforeEach(() => {
  home = mkdtempSync(join(tmpdir(), "amsg-sess-"));
});
afterEach(() => {
  rmSync(home, { recursive: true, force: true });
});

const sample = {
  serverUrl: "https://msg.agentmsg.org",
  sessionId: "sid123",
  token: "tok_secret",
  githubLogin: "alice",
  githubUserId: "42",
  publicKey: "PK==",
  privateKey: "SK==",
};

describe("SessionStore", () => {
  it("returns null when no session exists", () => {
    expect(new SessionStore(home).load()).toBeNull();
  });

  it("saves and loads a session round-trip", () => {
    const s = new SessionStore(home);
    s.save(sample);
    expect(s.load()).toEqual(sample);
  });

  it("writes the session file with owner-only permissions (0600)", () => {
    const s = new SessionStore(home);
    s.save(sample);
    const mode = statSync(join(home, "session.json")).mode & 0o777;
    expect(mode).toBe(0o600);
  });

  it("clear removes the session", () => {
    const s = new SessionStore(home);
    s.save(sample);
    s.clear();
    expect(s.load()).toBeNull();
  });

  it("a corrupt session file loads as null rather than throwing", () => {
    const s = new SessionStore(home);
    s.save(sample);
    // Overwrite with garbage
    const fs = require("node:fs");
    fs.writeFileSync(join(home, "session.json"), "{not json");
    expect(s.load()).toBeNull();
  });
});
