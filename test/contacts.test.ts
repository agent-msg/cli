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
    c.add("carol", { sessionId: "sid_c", publicKey: "PK_c", githubUserId: "55" });
    expect(c.resolve("carol")).toEqual({ sessionId: "sid_c", publicKey: "PK_c", githubUserId: "55" });
  });

  it("resolves a raw session id even if not a saved contact (no pubkey)", () => {
    const c = new Contacts(home);
    // A 32-hex-ish session id passed directly still resolves to an address
    // with no known public key, so send falls back to plaintext.
    expect(c.resolve("deadbeef")).toEqual({ sessionId: "deadbeef", publicKey: "", githubUserId: "" });
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
