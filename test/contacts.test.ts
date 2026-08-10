import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Contacts } from "../src/contacts.js";

let home: string;
beforeEach(() => (home = mkdtempSync(join(tmpdir(), "amsg-contacts-"))));
afterEach(() => rmSync(home, { recursive: true, force: true }));

describe("Contacts", () => {
  it("resolve returns null only for the empty string", () => {
    expect(new Contacts(home).resolve("")).toBeNull();
  });

  it("adds and resolves a contact by name", () => {
    const c = new Contacts(home);
    c.add("carol", {
      sessionId: "sid_c", publicKey: "PK_c", githubUserId: "55",
      installationBoxKey: "IBK_c", installationId: "install_c",
    });
    expect(c.resolve("carol")).toEqual({
      sessionId: "sid_c", publicKey: "PK_c", githubUserId: "55",
      installationBoxKey: "IBK_c", installationId: "install_c",
    });
  });

  it("resolves a raw session id even if not a saved contact (no pubkey)", () => {
    const c = new Contacts(home);
    // A 32-hex-ish session id passed directly still resolves to an address
    // with no known public key, so send falls back to plaintext.
    expect(c.resolve("deadbeef")).toEqual({
      sessionId: "deadbeef", publicKey: "", githubUserId: "", installationBoxKey: "", installationId: "",
    });
  });

  // installationId must be a genuinely distinct field from sessionId: they
  // identify different things (a session vs. a machine) and must never be
  // conflated on disk.
  it("keeps installationId distinct from sessionId, and defaults a missing one to empty string", () => {
    const c = new Contacts(home);
    c.add("dave", {
      sessionId: "sid_d", publicKey: "PK_d", githubUserId: "77",
      installationBoxKey: "IBK_d", installationId: "install_d",
    });
    const saved = c.resolve("dave")!;
    expect(saved.installationId).toBe("install_d");
    expect(saved.installationId).not.toBe(saved.sessionId);

    // A contact saved before installationId existed (field omitted) must
    // load with installationId defaulted to "", not undefined and never
    // silently backfilled from sessionId.
    c.add("eve", { sessionId: "sid_e", publicKey: "PK_e", githubUserId: "88", installationBoxKey: "" } as any);
    expect(c.resolve("eve")!.installationId).toBe("");
  });

  it("prefers a saved contact over treating the arg as a raw sid", () => {
    const c = new Contacts(home);
    c.add("bob", { sessionId: "sid_b", publicKey: "PK_b", githubUserId: "99" });
    expect(c.resolve("bob")?.publicKey).toBe("PK_b");
  });

  it("persists across instances", () => {
    new Contacts(home).add("carol", { sessionId: "s", publicKey: "p", githubUserId: "1" });
    expect(new Contacts(home).resolve("carol")?.publicKey).toBe("p");
  });

  it("lists saved contacts", () => {
    const c = new Contacts(home);
    c.add("a", { sessionId: "sa", publicKey: "pa", githubUserId: "1" });
    c.add("b", { sessionId: "sb", publicKey: "pb", githubUserId: "2" });
    expect(c.list().map((x) => x.name).sort()).toEqual(["a", "b"]);
  });
});
