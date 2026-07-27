import {
  closeSync,
  constants,
  existsSync,
  fsyncSync,
  lstatSync,
  mkdirSync,
  openSync,
  readFileSync,
  renameSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { createHash, createPrivateKey, createPublicKey, generateKeyPairSync, sign } from "node:crypto";
import { dirname, join } from "node:path";
import { spawnSync } from "node:child_process";

const PKCS8_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");
const SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

export interface InstallationKey {
  publicKey: string;
  seed: Buffer;
  sign(payload: Uint8Array): string;
}

interface InstallationMeta {
  version: 1;
  algorithm: "ed25519";
  public_key: string;
  storage: "keychain" | "file";
}

function b64url(data: Uint8Array): string {
  return Buffer.from(data).toString("base64url");
}

export function installationKeyFromSeed(seed: Buffer): InstallationKey {
  if (seed.length !== 32) throw new Error("installation key seed must be 32 bytes");
  const privateKey = createPrivateKey({
    key: Buffer.concat([PKCS8_PREFIX, seed]),
    format: "der",
    type: "pkcs8",
  });
  const publicDER = createPublicKey(privateKey).export({ format: "der", type: "spki" }) as Buffer;
  const rawPublic = publicDER.subarray(publicDER.length - 32);
  return {
    publicKey: b64url(rawPublic),
    seed,
    sign: (payload) => b64url(sign(null, Buffer.from(payload), privateKey)),
  };
}

export function generateInstallationKey(): InstallationKey {
  const { privateKey } = generateKeyPairSync("ed25519");
  const der = privateKey.export({ format: "der", type: "pkcs8" }) as Buffer;
  return installationKeyFromSeed(Buffer.from(der.subarray(der.length - 32)));
}

function ensureSecureHome(home: string): void {
  if (existsSync(home)) {
    const st = lstatSync(home);
    if (st.isSymbolicLink() || !st.isDirectory()) {
      throw new Error(`unsafe AGENTMSG_HOME: ${home} must be a real directory`);
    }
  } else {
    mkdirSync(home, { recursive: true, mode: 0o700 });
  }
}

export function atomicWritePrivate(path: string, data: string | Buffer): void {
  const dir = dirname(path);
  ensureSecureHome(dir);
  if (existsSync(path) && lstatSync(path).isSymbolicLink()) {
    throw new Error(`refusing to replace symlink: ${path}`);
  }
  const tmp = `${path}.tmp-${process.pid}-${Date.now()}`;
  let fd = -1;
  try {
    fd = openSync(tmp, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL, 0o600);
    writeFileSync(fd, data);
    fsyncSync(fd);
    closeSync(fd);
    fd = -1;
    renameSync(tmp, path);
    // Persist the rename itself, not only the file contents. Some platforms
    // reject opening directories; the file remains safely written there.
    try {
      const dirFD = openSync(dir, constants.O_RDONLY);
      try {
        fsyncSync(dirFD);
      } finally {
        closeSync(dirFD);
      }
    } catch {
      // Best-effort on Windows/filesystems without directory fsync.
    }
  } finally {
    if (fd >= 0) closeSync(fd);
    rmSync(tmp, { force: true });
  }
}

function readSecureSeed(path: string): Buffer {
  const st = lstatSync(path);
  if (st.isSymbolicLink() || !st.isFile()) throw new Error("installation key must be a regular file");
  if ((st.mode & 0o077) !== 0) throw new Error("installation key permissions must be 0600");
  if (typeof process.getuid === "function" && st.uid !== process.getuid()) {
    throw new Error("installation key is owned by another user");
  }
  const seed = Buffer.from(readFileSync(path, "utf8").trim(), "base64url");
  if (seed.length !== 32) throw new Error("installation key file is corrupt");
  return seed;
}

function credentialName(home: string): string {
  return `installation-${createHash("sha256").update(home).digest("hex").slice(0, 24)}`;
}

function keychainGet(home: string): Buffer | null {
  if (process.env.AGENTMSG_DISABLE_KEYCHAIN === "1") return null;
  const name = credentialName(home);
  let result;
  if (process.platform === "darwin") {
    result = spawnSync("security", ["find-generic-password", "-a", name, "-s", "agentmsg", "-w"], {
      encoding: "utf8",
      timeout: 5_000,
      stdio: ["ignore", "pipe", "ignore"],
    });
  } else if (process.platform === "linux") {
    result = spawnSync("secret-tool", ["lookup", "service", "agentmsg", "account", name], {
      encoding: "utf8",
      timeout: 5_000,
      stdio: ["ignore", "pipe", "ignore"],
    });
  } else if (process.platform === "win32") {
    const script =
      "$v=(New-Object Windows.Security.Credentials.PasswordVault);" +
      `$c=$v.Retrieve('agentmsg','${name}');$c.RetrievePassword();[Console]::Out.Write($c.Password)`;
    result = spawnSync("powershell.exe", ["-NoProfile", "-NonInteractive", "-Command", script], {
      encoding: "utf8",
      timeout: 5_000,
      windowsHide: true,
      stdio: ["ignore", "pipe", "ignore"],
    });
  } else {
    return null;
  }
  if (result.status !== 0 || !result.stdout.trim()) return null;
  const seed = Buffer.from(result.stdout.trim(), "base64url");
  return seed.length === 32 ? seed : null;
}

function keychainSet(home: string, seed: Buffer): boolean {
  if (process.env.AGENTMSG_DISABLE_KEYCHAIN === "1") return false;
  const name = credentialName(home);
  const encoded = b64url(seed);
  let result;
  if (process.platform === "darwin") {
    // Omitting the argument after -w makes `security` read the secret from stdin.
    result = spawnSync("security", ["add-generic-password", "-U", "-a", name, "-s", "agentmsg", "-w"], {
      input: encoded + "\n",
      encoding: "utf8",
      timeout: 5_000,
      stdio: ["pipe", "ignore", "ignore"],
    });
  } else if (process.platform === "linux") {
    result = spawnSync(
      "secret-tool",
      ["store", "--label=AgentMsg installation key", "service", "agentmsg", "account", name],
      { input: encoded + "\n", encoding: "utf8", timeout: 5_000, stdio: ["pipe", "ignore", "ignore"] },
    );
  } else if (process.platform === "win32") {
    const script =
      "$p=[Console]::In.ReadToEnd().Trim();" +
      "$v=New-Object Windows.Security.Credentials.PasswordVault;" +
      `$v.Add((New-Object Windows.Security.Credentials.PasswordCredential('agentmsg','${name}',$p)))`;
    result = spawnSync("powershell.exe", ["-NoProfile", "-NonInteractive", "-Command", script], {
      input: encoded,
      encoding: "utf8",
      timeout: 5_000,
      windowsHide: true,
      stdio: ["pipe", "ignore", "ignore"],
    });
  } else {
    return false;
  }
  return result.status === 0;
}

export class InstallationStore {
  private readonly keyFile: string;
  private readonly metaFile: string;

  constructor(private readonly home: string) {
    this.keyFile = join(home, "installation.key");
    this.metaFile = join(home, "installation.json");
  }

  loadOrCreate(): InstallationKey {
    ensureSecureHome(this.home);
    let meta: InstallationMeta | null = null;
    if (existsSync(this.metaFile)) {
      if (lstatSync(this.metaFile).isSymbolicLink()) throw new Error("installation metadata cannot be a symlink");
      meta = JSON.parse(readFileSync(this.metaFile, "utf8")) as InstallationMeta;
    }
    let seed = meta?.storage === "keychain" ? keychainGet(this.home) : null;
    if (!seed && existsSync(this.keyFile)) seed = readSecureSeed(this.keyFile);
    if (meta && !seed) throw new Error("installation private key is unavailable; refusing to create a new identity");

    if (!seed) {
      const generated = generateInstallationKey();
      seed = generated.seed;
      const storage = keychainSet(this.home, seed) ? "keychain" : "file";
      if (storage === "file") atomicWritePrivate(this.keyFile, b64url(seed) + "\n");
      meta = { version: 1, algorithm: "ed25519", public_key: generated.publicKey, storage };
      atomicWritePrivate(this.metaFile, JSON.stringify(meta, null, 2) + "\n");
      return generated;
    }
    const key = installationKeyFromSeed(seed);
    if (meta && (meta.algorithm !== "ed25519" || meta.public_key !== key.publicKey)) {
      throw new Error("installation metadata does not match the private key");
    }
    if (!meta) {
      meta = { version: 1, algorithm: "ed25519", public_key: key.publicKey, storage: "file" };
      atomicWritePrivate(this.metaFile, JSON.stringify(meta, null, 2) + "\n");
    }
    return key;
  }
}
