import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtempSync, rmSync, statSync, mkdirSync, writeFileSync, chmodSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ContextKeys } from "../src/context.js";

let home: string;
beforeEach(() => (home = mkdtempSync(join(tmpdir(), "amsg-ctx-"))));
afterEach(() => rmSync(home, { recursive: true, force: true }));

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
