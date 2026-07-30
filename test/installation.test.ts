import { chmodSync, lstatSync, mkdtempSync, readFileSync, renameSync, rmSync, symlinkSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { InstallationStore } from "../src/installation.js";

let home: string;
const savedDisableKeychain = process.env.AGENTMSG_DISABLE_KEYCHAIN;
beforeEach(() => {
  home = mkdtempSync(join(tmpdir(), "agentmsg-installation-"));
  process.env.AGENTMSG_DISABLE_KEYCHAIN = "1";
});
afterEach(() => {
  if (savedDisableKeychain === undefined) delete process.env.AGENTMSG_DISABLE_KEYCHAIN;
  else process.env.AGENTMSG_DISABLE_KEYCHAIN = savedDisableKeychain;
  rmSync(home, { recursive: true, force: true });
});

describe("installation identity storage", () => {
  it("reuses one Ed25519 identity and stores fallback files owner-only", () => {
    const first = new InstallationStore(home).loadOrCreate();
    const second = new InstallationStore(home).loadOrCreate();
    expect(second.publicKey).toBe(first.publicKey);
    expect(second.seed.equals(first.seed)).toBe(true);
    if (process.platform !== "win32") {
      expect(lstatSync(join(home, "installation.key")).mode & 0o777).toBe(0o600);
      expect(lstatSync(join(home, "installation.json")).mode & 0o777).toBe(0o600);
    }
    expect(readFileSync(join(home, "installation.key"), "utf8")).not.toContain(first.publicKey);
  });

  it.skipIf(process.platform === "win32")("refuses an over-permissive private-key file", () => {
    new InstallationStore(home).loadOrCreate();
    chmodSync(join(home, "installation.key"), 0o644);
    expect(() => new InstallationStore(home).loadOrCreate()).toThrow(/permissions/);
  });

  it.skipIf(process.platform === "win32")("refuses a symlinked private-key file", () => {
    new InstallationStore(home).loadOrCreate();
    const keyPath = join(home, "installation.key");
    const target = join(home, "stolen");
    renameSync(keyPath, target);
    symlinkSync(target, keyPath);
    expect(() => new InstallationStore(home).loadOrCreate()).toThrow(/regular file/);
  });
});
