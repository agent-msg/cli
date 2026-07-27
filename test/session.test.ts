import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtempSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { RegistrationLock, SessionStore, sessionNeedsRegistration } from "../src/session.js";

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
    writeFileSync(join(home, "session.json"), "{not json");
    expect(s.load()).toBeNull();
  });

  it("keeps old Verified sessions compatible and refreshes expiring Guests", () => {
    expect(sessionNeedsRegistration(sample)).toBe(false);
    expect(sessionNeedsRegistration({ ...sample, expiresAt: new Date(Date.now() + 30_000).toISOString() })).toBe(true);
    expect(sessionNeedsRegistration({ ...sample, expiresAt: new Date(Date.now() + 120_000).toISOString() })).toBe(false);
  });

  it("serializes registration and releases the local lock", async () => {
    const first = new RegistrationLock(home);
    const second = new RegistrationLock(home);
    await first.acquire();
    await expect(second.acquire(10)).rejects.toThrow(/already in progress/);
    first.release();
    await expect(second.acquire(10)).resolves.toBeUndefined();
    second.release();
  });
});
