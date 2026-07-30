// Local session state: token + this session's E2EE keypair, persisted to
// AGENTMSG_HOME/session.json with owner-only permissions. The private key never
// leaves this file. One AGENTMSG_HOME = one session, so several homes on one
// machine hold independent sessions (and independent keys).
import { closeSync, constants, mkdirSync, openSync, readFileSync, writeFileSync, rmSync, statSync } from "node:fs";
import { join, basename } from "node:path";
import { homedir } from "node:os";
import { createHash, randomBytes } from "node:crypto";
import { atomicWritePrivate } from "./installation.js";

export interface AddressCard {
  version: number;
  service: string;
  identity_type: "guest" | "github";
  principal_id: string;
  installation_id: string;
  session_id: string;
  verified: boolean;
  expires_at?: string;
  public_key: string;
  signature: string;
  github_user_id?: string;
  github_login?: string;
}

export interface Session {
  nickname?: string;
  serverUrl: string;
  sessionId: string;
  token: string;
  githubLogin: string;
  githubUserId: string;
  publicKey: string;
  privateKey: string;
  identityType?: "guest" | "github";
  verified?: boolean;
  principalId?: string;
  installationId?: string;
  expiresAt?: string;
  addressCard?: AddressCard;
}

// A profile selects an isolated subdirectory of the base home, so several
// sessions can coexist on one machine without clobbering each other's keys.
// Restricted to a safe charset — no path separators or "..", so a profile can
// never escape the base home.
const PROFILE_RE = /^[A-Za-z0-9._-]+$/;

// Session-identifying env vars we have actually confirmed, in priority order.
// AGENTMSG_SESSION comes first: it is the escape hatch ANY harness (or human)
// can set when we cannot work the identity out ourselves.
const AGENT_SESSION_ENV = ["AGENTMSG_SESSION", "CLAUDE_CODE_SESSION_ID", "CLAUDE_SESSION_ID"];

// Agent CLIs multiply faster than we can hard-code them, and the ones we checked
// disagree on the noun — Codex calls a conversation a THREAD, not a SESSION. So
// after the confirmed list we sniff for the shape, restricted to known agent
// prefixes: a bare *_SESSION_ID would match iTerm and tmux, where a new terminal
// tab is emphatically NOT a new identity.
const AGENT_PREFIX = "(?:CLAUDE|CLAUDE_CODE|CODEX|CURSOR|OPENCLAW|AIDER|GEMINI|COPILOT|AMP|CLINE|WINDSURF|DEVIN|GOOSE|OPENHANDS)";
const SNIFF_RE = new RegExp(`^${AGENT_PREFIX}_[A-Z0-9_]*(?:SESSION|THREAD|CONVERSATION)(?:_ID)?$`);

// Two ways a name can match the shape but carry the wrong meaning:
//   volatile — changes per request/capture, so it would mint a new identity on
//     every command and demand a fresh register each time;
//   flag — a boolean ABOUT the session rather than an id OF it. Claude Code's
//     real CLAUDE_CODE_CHILD_SESSION=1 is exactly this, and trusting it would
//     collapse every session onto one home again — the very bug being fixed.
const VOLATILE_RE = /DEBUG|PROXY|TRACE|SPAN|REQUEST|CAPTURE|TMP|TEMP/;
const FLAG_RE = /CHILD|PARENT|ENABLE|DISABLE|^IS_|_IS_|^HAS_|_HAS_|COUNT|INDEX/;

// Belt and braces: whatever the name suggests, a boolean-ish or empty value is
// not an identifier. Real session ids are uuids, hashes or slugs.
const NOT_AN_ID_RE = /^(?:0|1|true|false|yes|no|on|off|none|null|undefined)$/i;

function looksLikeSessionId(v: string | undefined): v is string {
  const t = v?.trim();
  return !!t && t.length >= 3 && !NOT_AN_ID_RE.test(t);
}

// Markers that mean "a child process of some agent", without identifying which
// session. Enough to know isolation MATTERS here even when we cannot do it.
const AGENT_MARKER_ENV: Array<[string, string]> = [
  ["CLAUDECODE", "Claude Code"],
  ["CLAUDE_CODE_ENTRYPOINT", "Claude Code"],
  ["OPENCLAW_CLI", "openclaw"],
  ["OPENCLAW_SHELL", "openclaw"],
  ["CODEX_SANDBOX", "Codex"],
  ["CODEX_THREAD_ID", "Codex"],
  ["CURSOR_AGENT", "Cursor"],
  ["AI_AGENT", "an AI agent"],
];

/** The env var naming THIS agent session, or undefined if none does. */
function agentSessionVar(): string | undefined {
  for (const k of AGENT_SESSION_ENV) {
    if (looksLikeSessionId(process.env[k])) return k;
  }
  // Deterministic order: several matches must always resolve the same way.
  return Object.keys(process.env)
    .filter((k) => SNIFF_RE.test(k) && !VOLATILE_RE.test(k) && !FLAG_RE.test(k) && looksLikeSessionId(process.env[k]))
    .sort()[0];
}

/**
 * The profile implied by the agent session we are running inside, or undefined
 * when we cannot tell (a plain human shell — or an agent like openclaw that
 * spawns children without passing its session id down).
 *
 * Without this, every agent session on a machine shares ~/.agentmsg: they all
 * report the SAME address card, and they poll one inbox — so `receive --ack` in
 * one session silently consumes another's messages. Hashing keeps the value a
 * safe path segment whatever the harness put in the variable.
 */
export function agentSessionProfile(): string | undefined {
  const k = agentSessionVar();
  if (!k) return undefined;
  return "s-" + createHash("sha256").update(process.env[k]!.trim()).digest("hex").slice(0, 12);
}

/**
 * The agent runtime we appear to be running inside, or undefined for a plain
 * human shell. Used to tell "no isolation needed" apart from "isolation needed
 * but impossible" — the latter deserves a loud error rather than silent sharing.
 */
export function detectAgentRuntime(): string | undefined {
  for (const [k, name] of AGENT_MARKER_ENV) {
    if (process.env[k]?.trim()) return name;
  }
  return agentSessionVar() ? "an AI agent" : undefined;
}

/** A distinct, pasteable identity for a human to pin this session with. */
export function suggestedSessionName(): string {
  return `${basename(process.cwd()).replace(/[^A-Za-z0-9._-]/g, "") || "agent"}-${randomBytes(3).toString("hex")}`;
}

/** The base home, before any profile subdirectory is applied. */
export function baseHome(): string {
  return process.env.AGENTMSG_HOME || join(homedir(), ".agentmsg");
}

export function defaultHome(profile?: string): string {
  const base = baseHome();
  // Precedence: --profile > AGENTMSG_PROFILE > the enclosing agent session.
  // "." is the explicit opt-out — it means "the one shared machine identity".
  const explicit = profile ?? process.env.AGENTMSG_PROFILE;
  if (explicit === "." ) return base;
  const p = explicit ?? agentSessionProfile();
  if (!p) return base;
  if (!PROFILE_RE.test(p) || p === "..") {
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

  /** Local read cursor: the last inbox seq acked in this home. `receive`
   *  defaults to showing messages after it, so ack actually consumes messages. */
  readCursor(): number {
    try {
      const c = JSON.parse(readFileSync(join(this.home, "cursor.json"), "utf8")) as { cursor?: number };
      return typeof c.cursor === "number" ? c.cursor : 0;
    } catch {
      return 0; // missing or corrupt → start from the beginning
    }
  }

  writeCursor(seq: number): void {
    mkdirSync(this.home, { recursive: true, mode: 0o700 });
    writeFileSync(join(this.home, "cursor.json"), JSON.stringify({ cursor: seq }), { mode: 0o600 });
  }

  save(s: Session): void {
    mkdirSync(this.home, { recursive: true, mode: 0o700 });
    atomicWritePrivate(this.file, JSON.stringify(s, null, 2) + "\n");
  }

  clear(): void {
    rmSync(this.file, { force: true });
  }
}

/** Old Verified sessions have no expiry and remain compatible. */
export function sessionNeedsRegistration(s: Session, now = Date.now(), skewMs = 60_000): boolean {
  if (!s.expiresAt) return false;
  const expires = Date.parse(s.expiresAt);
  return !Number.isFinite(expires) || expires - now <= skewMs;
}

export class RegistrationLock {
  private readonly file: string;
  private readonly owner = randomBytes(16).toString("hex");
  private fd = -1;

  constructor(private readonly home: string) {
    this.file = join(home, "registration.lock");
  }

  async acquire(timeoutMs = 30_000): Promise<void> {
    mkdirSync(this.home, { recursive: true, mode: 0o700 });
    const deadline = Date.now() + timeoutMs;
    for (;;) {
      try {
        this.fd = openSync(this.file, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL, 0o600);
        writeFileSync(this.fd, JSON.stringify({
          pid: process.pid,
          owner: this.owner,
          created_at: new Date().toISOString(),
        }));
        return;
      } catch (error) {
        const e = error as NodeJS.ErrnoException;
        if (e.code !== "EEXIST") throw error;
        try {
          // Device Flow can legitimately take up to 15 minutes, so a lock must
          // not be stolen while its owner is waiting for the human.
          if (Date.now() - statSync(this.file).mtimeMs > 20 * 60_000) {
            rmSync(this.file, { force: true });
            continue;
          }
        } catch {
          continue;
        }
        if (Date.now() >= deadline) throw new Error("another registration is already in progress");
        await new Promise<void>((resolve) => setTimeout(resolve, 100));
      }
    }
  }

  release(): void {
    if (this.fd >= 0) {
      closeSync(this.fd);
      this.fd = -1;
    }
    try {
      const current = JSON.parse(readFileSync(this.file, "utf8")) as { owner?: string };
      if (current.owner === this.owner) rmSync(this.file, { force: true });
    } catch {
      // Missing/replaced locks do not belong to this instance.
    }
  }
}
