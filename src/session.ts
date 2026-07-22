// Local session state: token + this session's E2EE keypair, persisted to
// AGENTMSG_HOME/session.json with owner-only permissions. The private key never
// leaves this file. One AGENTMSG_HOME = one session, so several homes on one
// machine hold independent sessions (and independent keys).
import { mkdirSync, readFileSync, writeFileSync, rmSync, chmodSync } from "node:fs";
import { join } from "node:path";
import { homedir } from "node:os";

export interface Session {
  serverUrl: string;
  sessionId: string;
  token: string;
  githubLogin: string;
  githubUserId: string;
  publicKey: string;
  privateKey: string;
}

// A profile selects an isolated subdirectory of the base home, so several
// sessions can coexist on one machine without clobbering each other's keys.
// Restricted to a safe charset — no path separators or "..", so a profile can
// never escape the base home.
const PROFILE_RE = /^[A-Za-z0-9._-]+$/;

export function defaultHome(profile?: string): string {
  const base = process.env.AGENTMSG_HOME || join(homedir(), ".agentmsg");
  const p = profile ?? process.env.AGENTMSG_PROFILE;
  if (!p) return base;
  if (!PROFILE_RE.test(p) || p === "." || p === "..") {
    throw new Error(`invalid profile "${p}": use letters, numbers, '.', '-' or '_' (no path separators)`);
  }
  return join(base, p);
}

export class SessionStore {
  private file: string;
  constructor(private home: string = defaultHome()) {
    this.file = join(home, "session.json");
  }

  load(): Session | null {
    try {
      return JSON.parse(readFileSync(this.file, "utf8")) as Session;
    } catch {
      return null; // missing or corrupt
    }
  }

  /** True if a session is already registered in this home. */
  exists(): boolean {
    return this.load() !== null;
  }

  save(s: Session): void {
    mkdirSync(this.home, { recursive: true, mode: 0o700 });
    writeFileSync(this.file, JSON.stringify(s, null, 2), { mode: 0o600 });
    chmodSync(this.file, 0o600); // enforce even if the file pre-existed
  }

  clear(): void {
    rmSync(this.file, { force: true });
  }
}
