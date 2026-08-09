import { chmodSync, lstatSync, mkdtempSync, readFileSync, renameSync, rmSync, symlinkSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { randomBytes } from "node:crypto";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { InstallationStore, installationBoxKeys, installationKeyFromSeed } from "../src/installation.js";
import { open, seal } from "../src/crypto.js";

let home: string;
const savedDisableKeychain = process.env.AGENTMSG_DISABLE_KEYCHAIN;
const savedSkipWindowsAcl = process.env.AGENTMSG_TEST_SKIP_WINDOWS_ACL;
beforeEach(() => {
  home = mkdtempSync(join(tmpdir(), "agentmsg-installation-"));
  process.env.AGENTMSG_DISABLE_KEYCHAIN = "1";
  process.env.AGENTMSG_TEST_SKIP_WINDOWS_ACL = "1";
});
afterEach(() => {
  if (savedDisableKeychain === undefined) delete process.env.AGENTMSG_DISABLE_KEYCHAIN;
  else process.env.AGENTMSG_DISABLE_KEYCHAIN = savedDisableKeychain;
  if (savedSkipWindowsAcl === undefined) delete process.env.AGENTMSG_TEST_SKIP_WINDOWS_ACL;
  else process.env.AGENTMSG_TEST_SKIP_WINDOWS_ACL = savedSkipWindowsAcl;
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

describe("installationBoxKeys", () => {
  it("is deterministic: the same seed yields the same X25519 pair across calls", () => {
    const seed = randomBytes(32);
    const first = installationBoxKeys(seed);
    const second = installationBoxKeys(seed);
    expect(first.publicKey).toBe(second.publicKey);
    expect(first.privateKey).toBe(second.privateKey);
  });

  it("is distinct: different seeds yield different X25519 pairs", () => {
    const a = installationBoxKeys(randomBytes(32));
    const b = installationBoxKeys(randomBytes(32));
    expect(a.publicKey).not.toBe(b.publicKey);
    expect(a.privateKey).not.toBe(b.privateKey);
  });

  it("is separated: the derived X25519 public key is not the Ed25519 public key from the same seed", () => {
    const seed = randomBytes(32);
    const boxKeys = installationBoxKeys(seed);
    const signKey = installationKeyFromSeed(seed);
    expect(boxKeys.publicKey).not.toBe(signKey.publicKey);
  });

  it("is functional: seal()/open() round-trips using the derived pair", async () => {
    const seed = randomBytes(32);
    const boxKeys = installationBoxKeys(seed);
    const ciphertext = await seal("hello installation", boxKeys.publicKey);
    const plaintext = await open(ciphertext, boxKeys.publicKey, boxKeys.privateKey);
    expect(plaintext).toBe("hello installation");
  });
});
