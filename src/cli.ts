#!/usr/bin/env node
// agentmsg CLI. Encryption is the default: when the recipient's public key is
// known (a saved contact), the message body is sealed on THIS machine before it
// reaches the client, so the server only ever sees ciphertext.
import { generateKeypair, seal, open, sealBytes, openBytes, generateContextKey, encryptSym, decryptSym } from "./crypto.js";
import { Client, ApiError, VersionConflict, ContextDTO, KeyEnvelope } from "./client.js";
import {
  SessionStore,
  Session,
  defaultHome,
  baseHome,
  detectAgentRuntime,
  agentSessionProfile,
  suggestedSessionName,
  sessionNeedsRegistration,
  RegistrationLock,
} from "./session.js";
import { Contacts, fingerprint } from "./contacts.js";
import { deviceFlowToken, DEFAULT_CLIENT_ID } from "./github.js";
import { normalizeServerUrl } from "./serverurl.js";
import { InstallationStore } from "./installation.js";
import { installationBoxKeys, InstallationBoxKeys } from "./installation-box.js";
import { CLI_VERSION, registerGuestFirst } from "./guest.js";
import { ContextKeys } from "./context.js";
import { encodeRecoveryCode, decodeRecoveryCode } from "./recovery.js";
import { existsSync, mkdirSync, readFileSync, writeFileSync, copyFileSync } from "node:fs";
import { basename, dirname, join } from "node:path";
import { homedir } from "node:os";
import { fileURLToPath } from "node:url";
import { createHash } from "node:crypto";

const USAGE = `agentmsg — end-to-end encrypted messaging between AI agent sessions

Usage:
  agentmsg register [--name NAME] [--verified] [--profile NAME] Guest first
  agentmsg whoami                                       show your address card
  agentmsg card [--qr]                                  print a compact address card
  agentmsg contact add NAME --sid SID --pubkey PK [--user ID] [--installation-box-key KEY] [--installation-id ID]
  agentmsg contact list
  agentmsg policy set --mode MODE [--allow a,b] [--i-understand-the-risk]
  agentmsg send --to NAME|SID --text TEXT [--file PATH] encrypts; --file attaches (Pro, E2EE)
  agentmsg download --msg ID --file NAME [--out PATH]   download + decrypt an attachment
  agentmsg receive [--ack] [--all] [--after N] [--watch] [--max N]  unread or stream live; decrypts
  agentmsg feedback --text TEXT [--kind bug|feature|other]  send feedback (10/day)
  agentmsg subscribe [--manage]                         Pro ($8/month, Stripe)
  agentmsg billing
  agentmsg unregister
  agentmsg skill install [--target claude|codex|all] [--force]
  agentmsg context create|list|get|set|share|revoke  shared context (E2EE)
  agentmsg context export-recovery --id ID              owner only; reprints the recovery code
  agentmsg context import-recovery --id ID --code CODE  restore a lost local key from a recovery code

Env: AGENTMSG_SERVER (default https://msg.agentmsg.org; read only by 'register' —
other commands use the server saved in the session), AGENTMSG_HOME, AGENTMSG_PROFILE
Profiles: inside an agent session a profile is derived automatically, so each
session has its own card and inbox. --profile NAME (or AGENTMSG_PROFILE) picks one
explicitly; AGENTMSG_PROFILE=. means the single shared machine identity.`;

const REGISTER_USAGE = `Usage:
  agentmsg register [--verified] [--profile NAME] [--force]

By default AgentMsg reuses this installation's Ed25519 identity and tries a
short-lived Guest registration first. Medium-risk registration may compute a
proof of work. High-risk registration asks the human to complete GitHub Device
Flow. --verified skips Guest and uses the legacy GitHub registration directly.

Guest identities are temporary and unverified. They have no github_user_id,
cannot use git_user authorization, cannot send attachments, and should be
authorized by session_id. Re-registering after expiry may change session_id.`;

const DEFAULT_SERVER = "https://msg.agentmsg.org";

interface Args {
  _: string[];
  flags: Record<string, string | boolean | string[]>;
}

// Minimal flag parser: --k v and --bool, plus positionals in `_`. A repeated
// "--k v" (e.g. several --file) accumulates into a string[].
function parseArgs(argv: string[]): Args {
  const out: Args = { _: [], flags: {} };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a.startsWith("--")) {
      const key = a.slice(2);
      const next = argv[i + 1];
      if (next !== undefined && !next.startsWith("--")) {
        const cur = out.flags[key];
        if (cur === undefined) out.flags[key] = next;
        else if (Array.isArray(cur)) cur.push(next);
        else out.flags[key] = [cur as string, next];
        i++;
      } else {
        out.flags[key] = true;
      }
    } else {
      out._.push(a);
    }
  }
  return out;
}

// Normalize a flag value (undefined | string | boolean | string[]) to a string[].
function flagList(v: string | boolean | string[] | undefined): string[] {
  if (v === undefined || typeof v === "boolean") return [];
  return Array.isArray(v) ? v : [v];
}

function emit(obj: unknown): void {
  process.stdout.write(JSON.stringify(obj, null, 2) + "\n");
}

function compactCard(s: Session): string {
  const payload = { v: 1, name: s.nickname || undefined, sid: s.sessionId, pk: s.publicKey,
    uid: s.githubUserId || undefined, exp: s.expiresAt || undefined, ibk: s.installationBoxKey || undefined,
    iid: s.installationId || undefined };
  return `am1:${Buffer.from(JSON.stringify(payload)).toString("base64url")}`;
}
function note(msg: string): void {
  process.stderr.write(msg + "\n");
}

// The recovery code for a shared context is shown here and ONLY here (at
// `create`, and again on an owner-invoked `export-recovery`) — never logged,
// never included in emit()'s machine-readable JSON on stdout, and never sent
// anywhere. See src/recovery.ts and docs/shared-context-keys.html for why:
// the code is generated client-side from a key the server has never seen, and
// that property only holds if nothing ever puts the code on the wire.
function printRecoveryCode(contextId: string, keyB64: string): void {
  const code = encodeRecoveryCode(keyB64);
  const bar = "=".repeat(70);
  note("");
  note(bar);
  note(`RECOVERY CODE for context ${contextId} — shown once, right now.`);
  note("");
  note(`    ${code}`);
  note("");
  note("This code can restore the ENTIRE context. Write it down or store it");
  note("somewhere offline (paper, a safe, an offline password manager). Do NOT");
  note("paste it into chat, email, a repo, or anywhere else connected to the");
  note("internet — anyone who has it can decrypt everything in this context.");
  note(bar);
  note("");
}

function cmdSkill(args: ReturnType<typeof parseArgs>): number {
  if (args._[0] !== "install") {
    note("usage: agentmsg skill install [--target claude|codex|all] [--force]");
    return 2;
  }
  const target = String(args.flags.target || "all");
  if (!["claude", "codex", "all"].includes(target)) {
    note("error: --target must be claude, codex, or all");
    return 2;
  }
  const source = join(dirname(fileURLToPath(import.meta.url)), "..", "SKILL.md");
  if (!existsSync(source)) {
    note("error: packaged SKILL.md is missing");
    return 1;
  }
  const home = homedir();
  const targets = target === "all" ? ["claude", "codex"] : [target];
  for (const name of targets) {
    const destination = join(home, name === "claude" ? ".claude" : ".codex", "skills", "agent-msg", "SKILL.md");
    if (existsSync(destination) && args.flags.force !== true) {
      note(`skip: ${destination} already exists (use --force to replace it)`);
      continue;
    }
    mkdirSync(dirname(destination), { recursive: true });
    copyFileSync(source, destination);
    note(`installed: ${destination}`);
  }
  return 0;
}

function loadSessionOrExit(store: SessionStore, home?: string): Session {
  const s = store.load();
  if (!s) {
    note("no active session; run 'agentmsg register' first");
    // This session got its own home (auto-derived from the agent session it runs
    // in). If a session predating that isolation sits in the shared base home,
    // it is not gone — it just isn't ours. Say where it is and how to adopt it.
    const base = baseHome();
    if (home && home !== base && new SessionStore(base).exists()) {
      note(`   note: this agent session uses its own home (${home}), so sessions no longer collide.`);
      note(`   An existing shared session is in ${base} — to use that one instead:`);
      note(`      export AGENTMSG_PROFILE=.`);
    }
    process.exit(1);
  }
  if (sessionNeedsRegistration(s)) {
    note("session is expired or within 60 seconds of expiry; run 'agentmsg register' to refresh it");
    process.exit(1);
  }
  return s;
}

function sessionOutput(s: Session, home: string): Record<string, unknown> {
  return {
    identity_type: s.identityType || "github",
    verified: s.verified ?? true,
    principal_id: s.principalId,
    installation_id: s.installationId,
    session_id: s.sessionId,
    expires_at: s.expiresAt,
    github_login: s.githubLogin || undefined,
    github_user_id: s.githubUserId || undefined,
    public_key: s.publicKey,
    installation_box_key: s.installationBoxKey,
    service: s.serverUrl,
    server: s.serverUrl,
    address_card: s.addressCard,
    home,
  };
}

function noteAddressCard(s: Session): void {
  note("Address card (share only over a trusted channel):");
  note(`  session_id: ${s.sessionId}`);
  note(`  public_key: ${s.publicKey}`);
  if (s.installationId) note(`  installation_id: ${s.installationId}`);
  if (s.installationBoxKey) note(`  installation_box_key: ${s.installationBoxKey}`);
  if (s.githubUserId) note(`  github_user_id: ${s.githubUserId}`);
  if (s.expiresAt) note(`  expires_at: ${s.expiresAt}`);
}

export async function run(argv: string[]): Promise<number> {
  const [cmd, ...rest] = argv;
  const args = parseArgs(rest);
  const server = (process.env.AGENTMSG_SERVER as string) || DEFAULT_SERVER;

  try {
    // --profile NAME (or AGENTMSG_PROFILE) isolates a session in its own subdir
    // of AGENTMSG_HOME, so several sessions coexist on one machine. Resolving it
    // here (inside try) means an invalid profile is reported cleanly.
    const profile = args.flags.profile ? String(args.flags.profile) : undefined;
    const home = defaultHome(profile);
    const store = new SessionStore(home);
    const contacts = new Contacts(home);
    switch (cmd) {
      case "register":
        return await cmdRegister(args, store, server, home);
      case "skill":
        return cmdSkill(args);
      case "whoami": {
        const s = loadSessionOrExit(store, home);
        emit(sessionOutput(s, home));
        return 0;
      }
      case "card": {
        const s = loadSessionOrExit(store, home);
        emit({
          card: compactCard(s), nickname: s.nickname || undefined, session_id: s.sessionId,
          public_key: s.publicKey, installation_box_key: s.installationBoxKey,
          installation_id: s.installationId,
        });
        return 0;
      }
      case "contact":
        return cmdContact(args, contacts);
      case "context":
        return await cmdContext(args, store, home);
      case "policy":
        return await cmdPolicy(args, store, home);
      case "send":
        return await cmdSend(args, store, contacts, home);
      case "download":
        return await cmdDownload(args, store, home);
      case "receive":
        return await cmdReceive(args, store, home);
      case "feedback":
        return await cmdFeedback(args, store, home);
      case "subscribe":
        return await cmdSubscribe(args, store, home);
      case "billing": {
        const s = loadSessionOrExit(store, home);
        emit(await new Client(s.serverUrl, s.token).billing());
        return 0;
      }
      case "unregister": {
        const s = loadSessionOrExit(store, home);
        await new Client(s.serverUrl, s.token).unregister();
        store.clear();
        emit({ status: "unregistered" });
        return 0;
      }
      case "-h":
      case "--help":
      case "help":
      case undefined:
        process.stdout.write(USAGE + "\n");
        return cmd === undefined ? 2 : 0;
      default:
        note(`unknown command '${cmd}'\n\n${USAGE}`);
        return 2;
    }
  } catch (e) {
    if (e instanceof ApiError) {
      if (e.code === "guest_registration_closed") {
        note("Guest registration is not open on this server. Retry with 'agentmsg register --verified'.");
      } else if (e.code === "registration_closed") {
        note("All registration is temporarily closed. Please try again later.");
      } else if (e.status === 429) {
        note(`Registration is rate limited (${e.code}).${e.retryAfter ? ` Retry after ${e.retryAfter}s.` : ""}`);
      } else {
        note(`error: server error ${e.status}: ${e.code} (${e.message})`);
      }
    } else {
      note(`error: ${(e as Error).message}`);
    }
    return 1;
  }
}

async function cmdRegister(args: ReturnType<typeof parseArgs>, store: SessionStore, server: string, home: string): Promise<number> {
  if (args.flags.help === true) {
    process.stdout.write(REGISTER_USAGE + "\n");
    return 0;
  }
  const existing = store.load();
  if (existing && !sessionNeedsRegistration(existing) && args.flags.force !== true && args.flags.verified !== true) {
    emit(sessionOutput(existing, home));
    noteAddressCard(existing);
    return 0;
  }
  // Some agents (openclaw, and any harness that spawns children without passing
  // its session id down) leave us able to detect that we are inside an agent but
  // unable to tell WHICH session. Minting an identity anyway would put every
  // session back on one card and one inbox — the exact bug isolation fixes, only
  // now invisible. Stop, and hand the human a value they can paste.
  const runtime = detectAgentRuntime();
  if (runtime && !agentSessionProfile() && !args.flags.profile && !process.env.AGENTMSG_PROFILE) {
    const suggestion = suggestedSessionName();
    note(`error: running inside ${runtime}, which does not expose a session id — cannot isolate this session automatically.`);
    note(`   Registering now would share one address card and one inbox with every other session here,`);
    note(`   so 'receive --ack' in one would consume another's messages.`);
    note(`   Give this session an identity, then re-run register:`);
    note(`      export AGENTMSG_SESSION=${suggestion}`);
    note(`   (any value unique to this session works; --profile <name> does the same)`);
    note(`   Deliberately sharing one identity machine-wide:  export AGENTMSG_PROFILE=.`);
    return 1;
  }
  // Validate the origin before any challenge, bearer token or GitHub token can
  // leave this machine.
  const raw = (args.flags.server as string) || server;
  const srv = normalizeServerUrl(raw, args.flags["allow-insecure-http"] === true);
  if (new URL(srv).origin !== new URL(DEFAULT_SERVER).origin) {
    note(`>> WARNING: registering with ${new URL(srv).origin}; registration credentials will be sent there.`);
  }
  const lock = new RegistrationLock(home);
  await lock.acquire();
  try {
    // A process that waited for the lock should reuse the winner's result.
    const current = store.load();
    if (current && !sessionNeedsRegistration(current) && args.flags.force !== true && args.flags.verified !== true) {
      emit(sessionOutput(current, home));
      noteAddressCard(current);
      return 0;
    }
    // Installation identity belongs to the MACHINE, not the session: it lives
    // in the base home so every agent session here shares one identity (and
    // therefore can decrypt the same shared-context keys). `home` is passed
    // as legacyHome so a pre-R7 identity already sitting in this session's
    // isolated profile dir gets promoted instead of orphaned.
    const installation = new InstallationStore(baseHome(), { legacyHome: home }).loadOrCreate();
    // Derived locally from the installation seed — always available with no
    // server round trip, and deterministic, so it never drifts between the
    // value we report at registration and the value we use for context
    // sealing/opening elsewhere in the CLI.
    const installationBoxKey = installationBoxKeys(installation.seed).publicKey;
    const client = new Client(srv);
    const ctl = new AbortController();
    const cancel = () => ctl.abort();
    process.once("SIGINT", cancel);
    try {
      if (args.flags.verified === true || args.flags["dev-user"]) {
        let credential: string;
        if (args.flags["dev-user"]) {
          const login = (args.flags["dev-login"] as string) || "";
          credential = login ? `${args.flags["dev-user"]}:${login}` : String(args.flags["dev-user"]);
        } else {
          credential = await deviceFlowToken({
            clientId: (args.flags["client-id"] as string) || DEFAULT_CLIENT_ID,
            signal: ctl.signal,
            onCode: (code, uri) => {
              note(`>> To register, open ${uri} in your browser and enter code: ${code}`);
              note(">> Waiting for authorization...");
            },
          });
        }
        let r;
        try {
          r = await client.register(credential);
        } finally {
          credential = "";
        }
        const kp = await generateKeypair();
        const session: Session = {
          nickname: args.flags.name ? String(args.flags.name) : undefined,
          serverUrl: srv,
          sessionId: r.session_id,
          token: r.token,
          githubLogin: r.github_login,
          githubUserId: r.github_user_id,
          publicKey: kp.publicKey,
          privateKey: kp.privateKey,
          identityType: "github",
          verified: true,
          installationBoxKey,
        };
        store.save(session);
        emit(sessionOutput(session, home));
        noteAddressCard(session);
        return 0;
      }

      const result = await registerGuestFirst({
        client,
        installation,
        serverOrigin: new URL(srv).origin,
        signal: ctl.signal,
        note,
        installationBoxKey,
      });
      const kp = await generateKeypair();
      const session: Session = {
        nickname: args.flags.name ? String(args.flags.name) : undefined,
        serverUrl: srv,
        sessionId: result.session_id,
        token: result.token,
        githubLogin: "github_login" in result ? result.github_login : "",
        githubUserId: "github_user_id" in result ? result.github_user_id : "",
        publicKey: kp.publicKey,
        privateKey: kp.privateKey,
        identityType: result.identity_type,
        verified: result.verified,
        principalId: result.principal_id,
        installationId: result.installation_id,
        expiresAt: "expires_at" in result ? result.expires_at : undefined,
        addressCard: result.address_card,
        installationBoxKey,
      };
      store.save(session);
      emit(sessionOutput(session, home));
      noteAddressCard(session);
      if (!session.verified) {
        note("Guest identity: temporary and unverified. Share session_id for authorization; attachments are disabled.");
      }
      return 0;
    } finally {
      process.removeListener("SIGINT", cancel);
    }
  } finally {
    lock.release();
  }
}

function cmdContact(args: ReturnType<typeof parseArgs>, contacts: Contacts): number {
  const sub = args._[0];
  if (sub === "add") {
    const compact = args.flags.card ? String(args.flags.card) : "";
    if (compact) {
      if (!compact.startsWith("am1:")) { note("error: invalid address card prefix"); return 2; }
      try {
        const p = JSON.parse(Buffer.from(compact.slice(4), "base64url").toString("utf8")) as
          { sid?: string; pk?: string; uid?: string; ibk?: string; iid?: string };
        if (!p.sid || !p.pk) throw new Error("missing sid or public key");
        const name = args._[1];
        if (!name) { note("usage: agentmsg contact add NAME --card CARD [--force]"); return 2; }
        contacts.add(
          name,
          {
            sessionId: p.sid, publicKey: p.pk, githubUserId: p.uid || "",
            installationBoxKey: p.ibk || "", installationId: p.iid || "",
          },
          args.flags.force === true,
        );
        emit({ status: "contact_saved", name, fingerprint: fingerprint(p.pk) });
        return 0;
      } catch { note("error: invalid address card"); return 2; }
    }
    const name = args._[1];
    if (!name || !args.flags.sid || !args.flags.pubkey) {
      note("usage: agentmsg contact add NAME --sid SID --pubkey PK [--user ID] [--installation-box-key KEY] [--installation-id ID] [--force]");
      return 2;
    }
    const pubkey = String(args.flags.pubkey);
    contacts.add(
      name,
      {
        sessionId: String(args.flags.sid), publicKey: pubkey,
        githubUserId: String(args.flags.user || ""),
        installationBoxKey: String(args.flags["installation-box-key"] || ""),
        installationId: String(args.flags["installation-id"] || ""),
      },
      args.flags.force === true,
    );
    // Show the fingerprint so the human can verify it out-of-band (SEC-05).
    emit({ status: "contact_saved", name, fingerprint: fingerprint(pubkey) });
    return 0;
  }
  if (sub === "list") {
    emit(contacts.list().map((c) => ({ ...c, fingerprint: fingerprint(c.publicKey) })));
    return 0;
  }
  note("usage: agentmsg contact add|list");
  return 2;
}

async function cmdPolicy(args: ReturnType<typeof parseArgs>, store: SessionStore, home?: string): Promise<number> {
  if (args._[0] !== "set") {
    note("usage: agentmsg policy set --mode MODE [--allow a,b] [--i-understand-the-risk]");
    return 2;
  }
  const s = loadSessionOrExit(store, home);
  const mode = String(args.flags.mode || "");
  const allow = args.flags.allow ? String(args.flags.allow).split(",").map((x) => x.trim()).filter(Boolean) : [];
  const ackRisk = args.flags["i-understand-the-risk"] === true;
  if (s.identityType === "guest" && mode !== "session_id") {
    note("error: Guest sessions can only use session_id policy; verify with GitHub for git_user policy.");
    return 1;
  }
  await new Client(s.serverUrl, s.token).setPolicy(mode, allow, ackRisk);
  emit({ status: "policy_updated", mode });
  return 0;
}

async function cmdSend(args: ReturnType<typeof parseArgs>, store: SessionStore, contacts: Contacts, home?: string): Promise<number> {
  const s = loadSessionOrExit(store, home);
  const to = String(args.flags.to || "");
  const text = args.flags.text !== undefined ? String(args.flags.text) : "";
  const files = flagList(args.flags.file);
  if (!to || (!text && files.length === 0)) {
    note("usage: agentmsg send --to NAME|SID --text TEXT [--file PATH ...]");
    return 2;
  }
  const addr = contacts.resolve(to)!;
  const pubkey = (args.flags["to-pubkey"] as string) || addr.publicKey;
  const client = new Client(s.serverUrl, s.token);

  if (files.length > 0 && s.identityType === "guest") {
    note("error: Guest sessions cannot send attachments; verify with GitHub first.");
    return 1;
  }

  // Attachments are ALWAYS end-to-end encrypted: without the recipient's public
  // key we cannot seal them, and the server refuses plaintext attachments.
  if (files.length > 0 && !pubkey) {
    note(`error: no public key for "${to}" — attachments must be end-to-end encrypted.`);
    note(`   Save the recipient's key: agentmsg contact add ${to} --sid <sid> --pubkey <pubkey>`);
    return 1;
  }

  // Seal the body (or, text-only, send plaintext with explicit consent).
  let body: string;
  let enc: string | undefined;
  if (pubkey) {
    body = await seal(text, pubkey); // encrypt on THIS machine
    enc = "box1";
  } else {
    // SEC-04: fail closed. Without a public key we would send plaintext, which
    // an automated agent must never do by accident. Refuse unless the human
    // explicitly opts into an unencrypted send.
    const forcedPlain = args.flags.plaintext === true && args.flags["i-understand-the-risk"] === true;
    if (!forcedPlain) {
      note(`error: no public key for "${to}" — refusing to send unencrypted.`);
      note(`   Save the recipient's key: agentmsg contact add ${to} --sid <sid> --pubkey <pubkey>`);
      note(`   Or, to send in the clear on purpose: add --plaintext --i-understand-the-risk`);
      return 1;
    }
    note(">> sending UNENCRYPTED (--plaintext)");
    body = text;
    enc = undefined;
  }

  // No attachments: single-shot send.
  if (files.length === 0) {
    const resp = await client.send({ to: addr.sessionId, text: body, enc });
    emit({ msg_id: resp.msg_id, seq: resp.seq, encrypted: !!enc });
    return 0;
  }

  // With attachments: seal each file locally, then two-phase upload. The bytes
  // and sha256 we declare describe the CIPHERTEXT — the server stores an opaque
  // blob it cannot read.
  const sealed = await Promise.all(
    files.map(async (p) => {
      const ct = await sealBytes(readFileSync(p), pubkey!);
      return { filename: basename(p), ct, sha256: createHash("sha256").update(ct).digest("hex") };
    }),
  );
  const seen = new Set<string>();
  for (const f of sealed) {
    if (seen.has(f.filename)) {
      note(`error: duplicate attachment filename "${f.filename}" — each attachment needs a distinct name.`);
      return 1;
    }
    seen.add(f.filename);
  }
  const attachments = sealed.map((f) => ({ filename: f.filename, mime: "application/octet-stream", bytes: f.ct.length, sha256: f.sha256 }));
  const resp = await client.send({ to: addr.sessionId, text: body, enc: "box1", attachments });
  for (const u of resp.uploads || []) {
    const f = sealed.find((x) => x.filename === u.filename);
    if (!f) throw new Error(`server issued an upload ticket for an unknown file: ${u.filename}`);
    await client.uploadPut(u.put_url, f.ct, "application/octet-stream");
  }
  const done = await client.commit(resp.msg_id);
  emit({ msg_id: done.msg_id, seq: done.seq, encrypted: true, attachments: attachments.map((a) => a.filename) });
  return 0;
}

async function cmdDownload(args: ReturnType<typeof parseArgs>, store: SessionStore, home?: string): Promise<number> {
  const s = loadSessionOrExit(store, home);
  const msgID = String(args.flags.msg || "");
  const filename = flagList(args.flags.file)[0] || "";
  if (!msgID || !filename) {
    note("usage: agentmsg download --msg MSG_ID --file FILENAME [--out PATH]");
    return 2;
  }
  const client = new Client(s.serverUrl, s.token);
  const ct = await client.download(`/v1/attachments/${encodeURIComponent(msgID)}/${encodeURIComponent(filename)}`);
  let plain: Uint8Array;
  try {
    plain = await openBytes(ct, s.publicKey, s.privateKey); // decrypt on THIS machine
  } catch {
    note("error: could not decrypt attachment — it was not sealed to this session's key.");
    return 1;
  }
  const out = args.flags.out ? String(args.flags.out) : filename;
  writeFileSync(out, plain, { mode: 0o600 });
  emit({ saved: out, bytes: plain.length });
  return 0;
}

// decryptMessage opens an enc:"box1" body with this session's keypair; other
// enc values or a failed decrypt yield a clear placeholder instead of throwing.
async function decryptOne(m: { text: string; enc?: string }, s: Session): Promise<{ text: string; encrypted: boolean; decrypt_error?: boolean }> {
  if (!m.enc) return { text: m.text, encrypted: false };
  if (m.enc !== "box1") return { text: "[unsupported encryption: " + m.enc + "]", encrypted: true, decrypt_error: true };
  try {
    return { text: await open(m.text, s.publicKey, s.privateKey), encrypted: true };
  } catch {
    return { text: "[could not decrypt — not encrypted to this session's key]", encrypted: true, decrypt_error: true };
  }
}

async function cmdReceive(args: ReturnType<typeof parseArgs>, store: SessionStore, home?: string): Promise<number> {
  const s = loadSessionOrExit(store, home);
  const client = new Client(s.serverUrl, s.token);
  // Default to unread-since-ack: start after the local read cursor, so `--ack`
  // actually consumes messages and the next `receive` only shows what's new.
  // `--all` shows the full history; `--after N` starts at an explicit seq.
  let after: number;
  if (args.flags.all === true) after = 0;
  else if (args.flags.after !== undefined) after = parseInt(String(args.flags.after), 10);
  else after = store.readCursor();

  if (!Number.isFinite(after) || after < 0) {
    note("error: --after must be a non-negative integer");
    return 2;
  }

  if (args.flags.watch === true) {
    return await cmdReceiveWatch(args, client, store, s, after);
  }

  const page = await client.inboxPage(after);
  const messages = await Promise.all(
    page.messages.map(async (m) => {
      const d = await decryptOne(m, s);
      return { seq: m.seq, msg_id: m.msg_id, from: m.from, ...d, attachments: m.attachments };
    }),
  );
  if (args.flags.ack && page.messages.length > 0) {
    const last = page.messages[page.messages.length - 1].seq;
    await client.ack(last);
    store.writeCursor(last); // advance the local read cursor past what we just acked
  }
  emit({ messages, cursor: page.cursor, next_cursor: page.next_cursor, has_more: page.has_more });
  return 0;
}

async function presentMessage(m: { seq: number; msg_id: string; from: string; text: string; enc?: string; attachments?: unknown[] }, s: Session) {
  const d = await decryptOne(m, s);
  return { seq: m.seq, msg_id: m.msg_id, from: m.from, ...d, attachments: m.attachments };
}

async function cmdReceiveWatch(
  args: ReturnType<typeof parseArgs>,
  client: Client,
  store: SessionStore,
  s: Session,
  startAfter: number,
): Promise<number> {
  const maxRaw = args.flags.max === undefined ? 0 : parseInt(String(args.flags.max), 10);
  if (!Number.isFinite(maxRaw) || maxRaw < 0) {
    note("error: --max must be a non-negative integer");
    return 2;
  }

  let after = startAfter;
  let seen = 0;
  let backoffMs = 500;
  for (;;) {
    try {
      for await (const m of client.inboxStream({ after })) {
        const out = await presentMessage(m, s);
        after = m.seq;
        emit({ message: out, cursor: after });
        if (args.flags.ack === true) {
          await client.ack(after);
          store.writeCursor(after);
        }
        seen++;
        if (maxRaw > 0 && seen >= maxRaw) return 0;
      }
      backoffMs = 500;
    } catch (e) {
      if ((e as Error).name === "AbortError") return 0;
      if (e instanceof ApiError) {
        if (e.status >= 400 && e.status < 500 && e.status !== 429) throw e;
        if (e.retryAfter > 0) backoffMs = Math.max(backoffMs, e.retryAfter * 1000);
      }
      note(`receive stream disconnected; retrying in ${Math.ceil(backoffMs / 1000)}s`);
      await new Promise<void>((resolve) => setTimeout(resolve, backoffMs));
      backoffMs = Math.min(backoffMs * 2, 30_000);
    }
  }
}

// Feedback goes to the operator, NOT to a peer — so unlike `send` there is
// nothing to encrypt it to, and it leaves this machine in the clear. Callers
// must know that before putting anything sensitive in it.
const FEEDBACK_KINDS = ["bug", "feature", "other"];

async function cmdFeedback(args: ReturnType<typeof parseArgs>, store: SessionStore, home?: string): Promise<number> {
  const text = args.flags.text !== undefined ? String(args.flags.text).trim() : "";
  if (!text) {
    note("usage: agentmsg feedback --text TEXT [--kind bug|feature|other]");
    return 2;
  }
  // Validate locally: --kind exists for triage, so a typo silently arriving as
  // "other" would quietly mislabel the report.
  const kind = args.flags.kind !== undefined ? String(args.flags.kind) : "";
  if (kind && !FEEDBACK_KINDS.includes(kind)) {
    note(`error: unknown --kind "${kind}" — use one of: ${FEEDBACK_KINDS.join(", ")}`);
    return 1;
  }
  const s = loadSessionOrExit(store, home);
  const r = await new Client(s.serverUrl, s.token).feedback({ text, kind: kind || undefined, client: clientTag() });
  emit(r);
  return 0;
}

// clientTag identifies the reporting CLI so the operator can reproduce a bug
// without asking what they were running.
function clientTag(): string {
  return `agentmsg/${cliVersion()} ${process.platform}-${process.arch}`;
}

let cachedVersion: string | undefined;
function cliVersion(): string {
  if (cachedVersion === undefined) {
    try {
      const pkgPath = join(dirname(fileURLToPath(import.meta.url)), "..", "package.json");
      cachedVersion = String((JSON.parse(readFileSync(pkgPath, "utf8")) as { version?: string }).version || "0.0.0");
    } catch {
      cachedVersion = "0.0.0"; // never fail a submission over a missing version
    }
  }
  return cachedVersion;
}

export interface ResolvedContextKey {
  key: string | undefined;
  /** True when we HAD a local key but it was for a different (or unknown)
   *  epoch than the server's current one, and re-importing the current
   *  envelope failed or wasn't possible — as opposed to never having had a
   *  key for this context at all. Lets callers give a more useful message:
   *  "wait for someone to redistribute the current key" reads very
   *  differently from "ask the owner to share it with you". */
  stale: boolean;
}

// Resolve a context's local decryption key, importing it from the server's
// `sealed_key` envelope when we don't have a CURRENT one. This is the
// receive side of member-to-member key distribution: a key gets sealed and
// uploaded by whoever answers (see answerPendingContextKeys below), but
// until something opens it and saves it locally, sharing never completes.
//
// Critical: a locally cached key is NEVER trusted just because it exists.
// ContextKeys has no way to know whether the server has since moved to a
// newer epoch (e.g. another member ran `revoke`, which now genuinely
// rotates — see that command below), so every call here re-checks the
// server's current epoch and discards + re-imports a stale local key. The
// alternative — trusting whatever is on disk — turns a successful rotation
// into a permanent, silent lockout for every remaining member: exactly the
// failure mode a real rotation is supposed to prevent, not cause.
async function resolveContextKey(
  client: Client,
  keys: ContextKeys,
  boxKeys: InstallationBoxKeys,
  id: string,
  dto?: ContextDTO,
): Promise<ResolvedContextKey> {
  const entry = keys.getEntry(id);
  const c = dto ?? (await client.getContext(id).catch(() => undefined));
  if (!c) {
    // Can't reach the server to check freshness — use whatever we have
    // locally rather than fail outright on a transient network error.
    return { key: entry?.key, stale: false };
  }
  if (entry && entry.epoch === c.epoch) return { key: entry.key, stale: false };
  // No local key, or one whose epoch doesn't confirm as current — including
  // a legacy entry with no epoch recorded at all, which is always treated as
  // stale rather than trusted. Try to import the current envelope.
  if (c.sealed_key) {
    try {
      const key = await open(c.sealed_key, boxKeys.publicKey, boxKeys.privateKey);
      keys.save(id, key, c.epoch);
      return { key, stale: false };
    } catch {
      // not addressed to us, or tampered — fall through to "stale"
    }
  }
  return { key: undefined, stale: entry !== undefined };
}

function noLocalKeyMessage(id: string, resolved: ResolvedContextKey): string {
  return resolved.stale
    ? `error: your local key for context ${id} is from an older epoch, and no current envelope has reached you yet. ` +
      `Wait for another organization member to run an agentmsg command (piggyback answering delivers it automatically), then retry.`
    : `error: no local key for context ${id} — ask the owner to share it again.`;
}

// Piggyback answering: rides on any context command the agent already runs.
// For each outstanding pending authorisation we hold the key for and know a
// public key for (a saved contact), seal it and upload. Quiet on success,
// and a failure here must never break the command the user actually asked
// for — hence the outer try/catch swallowing everything.
async function answerPendingContextKeys(
  client: Client,
  keys: ContextKeys,
  contacts: Contacts,
  selfInstallationId?: string,
): Promise<void> {
  try {
    const pending = await client.pendingContextKeys();
    if (!Array.isArray(pending) || pending.length === 0) return;
    const byContext = new Map<string, KeyEnvelope[]>();
    const book = contacts.list();
    for (const p of pending) {
      if (!p?.context_id || !p.recipient_installation) continue;
      if (selfInstallationId && p.recipient_installation === selfInstallationId) continue;
      const key = keys.get(p.context_id);
      if (!key) continue; // we can't answer for a context we hold no key for
      const contact = book.find((c) => c.githubUserId && c.githubUserId === p.github_user_id);
      // Seal to their INSTALLATION box key, not contact.publicKey (their
      // session's ephemeral messaging keypair) — sealing to the wrong key
      // produces an envelope their resolveContextKey() can never open. A
      // contact saved before this field existed has none yet; skip them
      // rather than send an unopenable envelope (see R4b).
      if (!contact?.installationBoxKey) continue;
      const sealedKey = await seal(key, contact.installationBoxKey);
      const list = byContext.get(p.context_id) ?? [];
      list.push({ recipient_installation: p.recipient_installation, sealed_key: sealedKey });
      byContext.set(p.context_id, list);
    }
    for (const [contextId, envelopes] of byContext) {
      await client.uploadContextKeys(contextId, envelopes).catch(() => {});
    }
  } catch {
    // Never let a failed answer break the command the user actually asked for.
  }
}

// Shared contexts. The document and its name are encrypted with a symmetric
// key held locally; the server stores ciphertext and a version number.
async function cmdContext(args: ReturnType<typeof parseArgs>, store: SessionStore, home: string): Promise<number> {
  const sub = args._[0];
  const s = loadSessionOrExit(store, home);
  const client = new Client(s.serverUrl, s.token);
  // contexts.json and the installation identity both belong to the machine,
  // not this session — they live in the base home (see cmdRegister for why),
  // with `home` (this session's isolated profile dir) as the legacy-migration
  // source for a pre-R7 identity.
  const keys = new ContextKeys(baseHome());
  const contacts = new Contacts(home);
  const installation = new InstallationStore(baseHome(), { legacyHome: home }).loadOrCreate();
  const boxKeys = installationBoxKeys(installation.seed);
  // The verified/dev-user registration response (POST /v1/register) does not
  // carry installation_id, unlike the guest flow — so a session created that
  // way has no s.installationId cached locally. Fall back to asking the
  // server for our own current address card, which always has it. This is
  // needed both to skip ourselves in the pending list below and to
  // self-address the envelope during a real key rotation on revoke.
  const selfInstallationId =
    s.installationId || (await client.addressCard().then((c) => c.installation_id).catch(() => undefined));

  // Any context command answers what pending authorisations it can, in
  // passing — no daemon, no separate command.
  await answerPendingContextKeys(client, keys, contacts, selfInstallationId);

  if (sub === "create") {
    const name = args.flags.name !== undefined ? String(args.flags.name) : "";
    if (!name) {
      note("usage: agentmsg context create --name NAME");
      return 2;
    }
    const key = await generateContextKey();
    const c = await client.createContext(await encryptSym(name, key));
    keys.save(c.id, key, c.epoch);
    // Shown once, right now — at the moment of creation, when the user's
    // attention is actually on this context and they're the one responsible
    // for it. Not an afterthought command the user has to think to run.
    printRecoveryCode(c.id, key);
    emit({ context_id: c.id, version: c.version, epoch: c.epoch });
    return 0;
  }

  if (sub === "list") {
    const list = await client.listContexts();
    emit(await Promise.all(list.map(async (c) => {
      const entry = keys.getEntry(c.id);
      let name = "[no local key]";
      if (entry && entry.epoch !== undefined && entry.epoch !== c.epoch) {
        // We know for certain this key is stale (unlike the legacy/unknown-
        // epoch case below, which is only a guess after a failed decrypt).
        name = `[cannot decrypt — key is from an older epoch; run 'agentmsg context get --id ${c.id}' to try re-importing]`;
      } else if (entry) {
        try {
          name = await decryptSym(c.name_enc, entry.key);
        } catch {
          name = "[cannot decrypt — key may be from an older epoch]";
        }
      }
      return { context_id: c.id, name, version: c.version, epoch: c.epoch, role: c.role };
    })));
    return 0;
  }

  if (sub === "get") {
    const id = String(args.flags.id || "");
    if (!id) {
      note("usage: agentmsg context get --id ID");
      return 2;
    }
    const c = await client.getContext(id);
    const resolved = await resolveContextKey(client, keys, boxKeys, id, c);
    if (!resolved.key) {
      note(noLocalKeyMessage(id, resolved));
      return 1;
    }
    const key = resolved.key;
    let text = "";
    if (c.download_url) {
      const ct = await client.download(new URL(c.download_url).pathname);
      try {
        text = await decryptSym(Buffer.from(ct).toString("utf8"), key);
      } catch {
        // Epoch matched, but the bytes didn't decrypt anyway — e.g. a
        // rotation that re-keyed but never finished re-encrypting content.
        // Never let the raw crypto exception reach the user.
        note(`error: could not decrypt content for context ${id} — the local key does not match the last write. ` +
          `This can happen mid-rotation; try again shortly, or ask the owner to confirm 'context revoke' completed.`);
        return 1;
      }
    }
    emit({ context_id: c.id, version: c.version, epoch: c.epoch, text });
    return 0;
  }

  if (sub === "set") {
    const id = String(args.flags.id || "");
    const text = args.flags.text !== undefined ? String(args.flags.text) : "";
    if (!id || !text) {
      note("usage: agentmsg context set --id ID --text TEXT [--expect VERSION]");
      return 2;
    }
    const resolved = await resolveContextKey(client, keys, boxKeys, id);
    if (!resolved.key) {
      note(noLocalKeyMessage(id, resolved));
      return 1;
    }
    const key = resolved.key;
    const expect = args.flags.expect !== undefined
      ? parseInt(String(args.flags.expect), 10)
      : (await client.getContext(id)).version;

    const ct = Buffer.from(await encryptSym(text, key), "utf8");
    const sha256 = createHash("sha256").update(ct).digest("hex");
    try {
      const ticket = await client.putContext(id, expect, ct.length, sha256);
      await client.uploadPut(ticket.upload_url, ct, "application/octet-stream");
      const done = await client.commitContext(id, expect, ct.length, sha256);
      emit({ context_id: id, version: done.version });
      return 0;
    } catch (e) {
      if (e instanceof VersionConflict) {
        // Conflicts are expected here, not exceptional. Tell the agent exactly
        // how to fetch the version it missed so it can merge and retry.
        note(`error: version_conflict — someone else wrote version ${e.currentVersion} while you were editing.`);
        note(`   Fetch it, merge your change into it, then retry with the new version:`);
        note(`      agentmsg context get --id ${id}`);
        note(`      agentmsg context set --id ${id} --text <merged> --expect ${e.currentVersion}`);
        return 1;
      }
      throw e;
    }
  }

  if (sub === "share") {
    const id = String(args.flags.id || "");
    const to = String(args.flags.to || "");
    const role = args.flags.role ? String(args.flags.role) : "writer";
    if (!id || !to) {
      note("usage: agentmsg context share --id ID --to NAME|SID [--role writer|reader]");
      return 2;
    }
    const resolved = await resolveContextKey(client, keys, boxKeys, id);
    if (!resolved.key) {
      note(noLocalKeyMessage(id, resolved));
      return 1;
    }
    const key = resolved.key;
    const addr = contacts.resolve(to);
    if (!addr?.publicKey || !addr.githubUserId) {
      note(`error: need a saved contact with a public key and numeric id for "${to}".`);
      note(`   agentmsg contact add ${to} --sid <sid> --pubkey <pubkey> --user <id>`);
      return 1;
    }
    // Context keys must be sealed to the recipient's INSTALLATION box key,
    // not addr.publicKey (their session's ephemeral messaging keypair) — the
    // two are independent X25519 pairs, and only the installation key is
    // opened by resolveContextKey() on their end (see R4b). A contact saved
    // before this field existed has none: degrade with a clear message
    // rather than send an envelope they can never open.
    if (!addr.installationBoxKey) {
      note(`error: this contact's card predates installation keys; ask them to re-share.`);
      note(`   They should re-run 'agentmsg whoami' or 'agentmsg card' and re-send you their card,`);
      note(`   then: agentmsg contact add ${to} --sid <sid> --pubkey <pubkey> --user <id> --installation-box-key <key> --force`);
      return 1;
    }
    // Envelopes MUST be addressed by the recipient's INSTALLATION id (stable
    // across their sessions), never a session id: the server stores this
    // value verbatim as ContextMember.RecipientInstallation, and the
    // recipient's read path looks envelopes up by their real
    // sess.InstallationID. Addressing by session id means the two never
    // match, so sealed_key is never returned to them — and because the
    // server treats a member as "already answered" once ANY envelope exists
    // under their stored value, the recipient is then permanently stuck
    // with no recovery path. A contact saved (or a card pasted) before
    // installation identity existed has no installationId: refuse here,
    // clearly, rather than silently falling back to sessionId.
    if (!addr.installationId) {
      note(`error: this contact's card predates installation identity; ask them to re-share their card.`);
      note(`   They should re-run 'agentmsg whoami' or 'agentmsg card' and re-send you their card,`);
      note(`   then: agentmsg contact add ${to} --sid <sid> --pubkey <pubkey> --user <id> --installation-box-key <key> --installation-id <id> --force`);
      return 1;
    }
    await client.addContextMember(id, addr.githubUserId, role, addr.installationId, await seal(key, addr.installationBoxKey));
    emit({ status: "shared", context_id: id, with: to, role });
    return 0;
  }

  if (sub === "revoke") {
    const id = String(args.flags.id || "");
    const uid = String(args.flags.user || "");
    if (!id || !uid) {
      note("usage: agentmsg context revoke --id ID --user GITHUB_USER_ID");
      return 2;
    }
    const oldEntry = keys.getEntry(id);
    const c = await client.removeContextMember(id, uid);

    // Honest revoke: bumping the epoch alone has zero cryptographic effect —
    // the removed member's old key still opens anything written afterward
    // unless the content is actually re-encrypted under a fresh key they
    // never receive. We can only do that if we hold the OLD key locally
    // (needed to decrypt existing content before re-encrypting it); if we
    // don't, we fall through having advanced the epoch but rotated nothing,
    // and print no claim of protection — a false security promise is worse
    // than a missing feature.
    let rotated = false;
    if (oldEntry) {
      const freshKey = await generateContextKey();
      // Commit the fresh key to LOCAL storage before any of the network
      // calls below that could fail partway through. This is what keeps
      // local state from ever lagging behind the server: even if content
      // re-encryption or delivery to other members fails, we already hold
      // the correct key for the new epoch (c.epoch, from the removal above,
      // which already bumped it) — so resolveContextKey's epoch check finds
      // a match on the very next command instead of a stale key nobody can
      // recover from. Import-on-read (the fix above) is what makes it safe
      // to commit here first: a mid-rotation crash now degrades to "retry",
      // not "permanently locked out."
      keys.save(id, freshKey, c.epoch);
      try {
        const full = await client.getContext(id);
        if (full.download_url && oldEntry.key) {
          const ct = await client.download(new URL(full.download_url).pathname);
          const plaintext = await decryptSym(Buffer.from(ct).toString("utf8"), oldEntry.key);
          const newCt = Buffer.from(await encryptSym(plaintext, freshKey), "utf8");
          const sha256 = createHash("sha256").update(newCt).digest("hex");
          const ticket = await client.putContext(id, full.version, newCt.length, sha256);
          await client.uploadPut(ticket.upload_url, newCt, "application/octet-stream");
          await client.commitContext(id, full.version, newCt.length, sha256);
        }
        // Deliver the fresh key to OURSELVES too: the server trusts the
        // owner unconditionally for this (see handleRotateKeys), and doing
        // so is what lets GET /v1/contexts/pending see us as a keyholder for
        // the new epoch — which is how we then discover the remaining
        // members to answer, via the exact piggyback path used elsewhere.
        if (selfInstallationId) {
          const selfSealed = await seal(freshKey, boxKeys.publicKey);
          await client.uploadContextKeys(id, [{ recipient_installation: selfInstallationId, sealed_key: selfSealed }]);
        } else {
          // Minor but real: don't silently claim success while skipping our
          // own delivery. The rotation itself (fresh key + re-encrypted
          // content, both already done above) is still genuine, but other
          // sessions on this machine won't be able to import it from the
          // server until this resolves.
          note("warning: could not resolve our own installation id, so the fresh key was not uploaded for the server to hand to other sessions on this machine. It is saved locally here, though.");
        }
        await answerPendingContextKeys(client, keys, contacts, selfInstallationId);
        rotated = true;
      } catch (e) {
        note(`warning: key rotation after revoke did not fully complete (${(e as Error).message}). ` +
          `The epoch was advanced and a fresh key is already saved locally here, so re-running should finish the job.`);
      }
    }

    if (rotated) {
      note(">> access revoked and the context key was rotated: the removed member's key no longer decrypts new writes.");
    } else {
      note(">> access revoked and key epoch advanced.");
    }
    note(">> NOTE: this does not undo anything the removed member already read — that copy is on their machine.");
    emit({ context_id: id, epoch: c.epoch, rotated });
    return 0;
  }

  if (sub === "export-recovery") {
    const id = String(args.flags.id || "");
    if (!id) {
      note("usage: agentmsg context export-recovery --id ID");
      return 2;
    }
    const c = await client.getContext(id);
    // Owner-only, by design: any keyholder could otherwise re-export the
    // recovery code, and a departing member who did so would keep permanent
    // full access that a subsequent key rotation cannot revoke (rotation
    // only stops NEW envelopes reaching them — it does nothing about a
    // recovery code they already hold). The role check trusts the server's
    // membership record, the one thing the server DOES get to decide.
    if (c.role !== "owner") {
      note(`error: export-recovery is owner-only — the server reports your role on context ${id} as "${c.role ?? "unknown"}".`);
      note("   Ask the context owner to export and share it with you instead.");
      return 1;
    }
    const resolved = await resolveContextKey(client, keys, boxKeys, id, c);
    if (!resolved.key) {
      note(noLocalKeyMessage(id, resolved));
      return 1;
    }
    printRecoveryCode(id, resolved.key);
    emit({ context_id: id, epoch: c.epoch });
    return 0;
  }

  if (sub === "import-recovery") {
    const id = String(args.flags.id || "");
    const code = args.flags.code !== undefined ? String(args.flags.code) : "";
    if (!id || !code) {
      note("usage: agentmsg context import-recovery --id ID --code CODE");
      return 2;
    }
    let key: string;
    try {
      key = decodeRecoveryCode(code);
    } catch (e) {
      note(`error: ${(e as Error).message}`);
      return 1;
    }
    // Best-effort epoch lookup: restoring the key locally is the whole point
    // of this command (it's meant to work even when things are in a bad
    // state), so a server that's unreachable right now must not block it —
    // the entry is simply saved with an "unknown" epoch, which downstream
    // reads already treat as needing a freshness check (see context.ts).
    let epoch: number | undefined;
    try {
      epoch = (await client.getContext(id)).epoch;
    } catch {
      // fall through with epoch left undefined
    }
    keys.save(id, key, epoch);
    emit({ context_id: id, epoch, status: "restored" });
    return 0;
  }

  note("usage: agentmsg context create|list|get|set|share|revoke|export-recovery|import-recovery");
  return 2;
}

async function cmdSubscribe(args: ReturnType<typeof parseArgs>, store: SessionStore, home?: string): Promise<number> {
  const s = loadSessionOrExit(store, home);
  const client = new Client(s.serverUrl, s.token);
  const { url } = args.flags.manage ? await client.portal() : await client.checkout();
  note(">> open this URL in a browser to continue:");
  emit({ url });
  return 0;
}

// Entry point (skipped when imported for tests).
const invokedDirectly = process.argv[1] && /(?:^|\/)(cli\.js|agentmsg)$/.test(process.argv[1]);
if (invokedDirectly) {
  run(process.argv.slice(2)).then((code) => process.exit(code));
}
