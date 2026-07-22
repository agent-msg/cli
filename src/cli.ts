#!/usr/bin/env node
// agentmsg CLI. Encryption is the default: when the recipient's public key is
// known (a saved contact), the message body is sealed on THIS machine before it
// reaches the client, so the server only ever sees ciphertext.
import { generateKeypair, seal, open } from "./crypto.js";
import { Client, ApiError } from "./client.js";
import { SessionStore, Session, defaultHome } from "./session.js";
import { Contacts, fingerprint } from "./contacts.js";
import { deviceFlowToken, DEFAULT_CLIENT_ID } from "./github.js";
import { normalizeServerUrl } from "./serverurl.js";

const USAGE = `agentmsg — end-to-end encrypted messaging between AI agent sessions

Usage:
  agentmsg register [--profile NAME] [--force]         register + generate keys
  agentmsg whoami                                       show your address card
  agentmsg contact add NAME --sid SID --pubkey PK [--user ID]
  agentmsg contact list
  agentmsg policy set --mode MODE [--allow a,b] [--i-understand-the-risk]
  agentmsg send --to NAME|SID --text TEXT               encrypts if pubkey known
  agentmsg receive [--after N] [--ack] [--watch]        decrypts automatically
  agentmsg subscribe [--manage]                         Pro ($8/month, Stripe)
  agentmsg billing
  agentmsg unregister

Env: AGENTMSG_SERVER (default https://msg.agentmsg.org), AGENTMSG_HOME, AGENTMSG_PROFILE
Profiles: use --profile NAME (or AGENTMSG_PROFILE) to keep several independent
sessions on one machine — each lives in AGENTMSG_HOME/NAME with its own keys.`;

const DEFAULT_SERVER = "https://msg.agentmsg.org";

interface Args {
  _: string[];
  flags: Record<string, string | boolean>;
}

// Minimal flag parser: --k v and --bool, plus positionals in `_`.
function parseArgs(argv: string[]): Args {
  const out: Args = { _: [], flags: {} };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a.startsWith("--")) {
      const key = a.slice(2);
      const next = argv[i + 1];
      if (next !== undefined && !next.startsWith("--")) {
        out.flags[key] = next;
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

function emit(obj: unknown): void {
  process.stdout.write(JSON.stringify(obj, null, 2) + "\n");
}
function note(msg: string): void {
  process.stderr.write(msg + "\n");
}

function loadSessionOrExit(store: SessionStore): Session {
  const s = store.load();
  if (!s) {
    note("no active session; run 'agentmsg register' first");
    process.exit(1);
  }
  return s;
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
      case "whoami": {
        const s = loadSessionOrExit(store);
        emit({ session_id: s.sessionId, github_login: s.githubLogin, github_user_id: s.githubUserId, public_key: s.publicKey, server: s.serverUrl });
        return 0;
      }
      case "contact":
        return cmdContact(args, contacts);
      case "policy":
        return await cmdPolicy(args, store);
      case "send":
        return await cmdSend(args, store, contacts);
      case "receive":
        return await cmdReceive(args, store);
      case "subscribe":
        return await cmdSubscribe(args, store);
      case "billing": {
        const s = loadSessionOrExit(store);
        emit(await new Client(s.serverUrl, s.token).billing());
        return 0;
      }
      case "unregister": {
        const s = loadSessionOrExit(store);
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
      note(`error: server error ${e.status}: ${e.code} (${e.message})`);
    } else {
      note(`error: ${(e as Error).message}`);
    }
    return 1;
  }
}

async function cmdRegister(args: ReturnType<typeof parseArgs>, store: SessionStore, server: string, home: string): Promise<number> {
  // Same-machine safety: never SILENTLY overwrite an existing session's keys and
  // token. Registering a second session on one machine must be a deliberate act
  // — use --profile <name> for an independent session, or --force to replace.
  if (store.exists() && args.flags.force !== true) {
    note(`error: a session already exists in ${home} — registering would overwrite its keys and token.`);
    note(`   Keep both — register the new session under its own profile:`);
    note(`      agentmsg register --profile <name>`);
    note(`   Or replace this session on purpose:  agentmsg register --force`);
    return 1;
  }
  // SEC-01: register sends the GitHub access token to this origin. Validate it
  // (https by default; loopback http only with --allow-insecure-http), and
  // surface a non-default origin before any credential leaves the machine.
  const raw = (args.flags.server as string) || server;
  const srv = normalizeServerUrl(raw, args.flags["allow-insecure-http"] === true);
  if (new URL(srv).origin !== new URL(DEFAULT_SERVER).origin) {
    note(`>> WARNING: registering with ${new URL(srv).origin} — your GitHub token and session token will be sent there.`);
  }
  let credential: string;
  if (args.flags["dev-user"]) {
    const login = (args.flags["dev-login"] as string) || "";
    credential = login ? `${args.flags["dev-user"]}:${login}` : String(args.flags["dev-user"]);
  } else {
    credential = await deviceFlowToken({
      clientId: (args.flags["client-id"] as string) || DEFAULT_CLIENT_ID,
      onCode: (code, uri) => {
        note(`>> To register, open ${uri} in your browser and enter code: ${code}`);
        note(">> Waiting for authorization...");
      },
    });
  }
  const client = new Client(srv);
  const r = await client.register(credential);
  const kp = await generateKeypair(); // one keypair per session
  const session: Session = {
    serverUrl: srv,
    sessionId: r.session_id,
    token: r.token,
    githubLogin: r.github_login,
    githubUserId: r.github_user_id,
    publicKey: kp.publicKey,
    privateKey: kp.privateKey,
  };
  store.save(session);
  emit({
    session_id: r.session_id,
    github_login: r.github_login,
    github_user_id: r.github_user_id,
    public_key: kp.publicKey,
  });
  return 0;
}

function cmdContact(args: ReturnType<typeof parseArgs>, contacts: Contacts): number {
  const sub = args._[0];
  if (sub === "add") {
    const name = args._[1];
    if (!name || !args.flags.sid || !args.flags.pubkey) {
      note("usage: agentmsg contact add NAME --sid SID --pubkey PK [--user ID] [--force]");
      return 2;
    }
    const pubkey = String(args.flags.pubkey);
    contacts.add(
      name,
      { sessionId: String(args.flags.sid), publicKey: pubkey, githubUserId: String(args.flags.user || "") },
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

async function cmdPolicy(args: ReturnType<typeof parseArgs>, store: SessionStore): Promise<number> {
  if (args._[0] !== "set") {
    note("usage: agentmsg policy set --mode MODE [--allow a,b] [--i-understand-the-risk]");
    return 2;
  }
  const s = loadSessionOrExit(store);
  const mode = String(args.flags.mode || "");
  const allow = args.flags.allow ? String(args.flags.allow).split(",").map((x) => x.trim()).filter(Boolean) : [];
  const ackRisk = args.flags["i-understand-the-risk"] === true;
  await new Client(s.serverUrl, s.token).setPolicy(mode, allow, ackRisk);
  emit({ status: "policy_updated", mode });
  return 0;
}

async function cmdSend(args: ReturnType<typeof parseArgs>, store: SessionStore, contacts: Contacts): Promise<number> {
  const s = loadSessionOrExit(store);
  const to = String(args.flags.to || "");
  const text = String(args.flags.text || "");
  if (!to || !text) {
    note("usage: agentmsg send --to NAME|SID --text TEXT");
    return 2;
  }
  const addr = contacts.resolve(to)!;
  const pubkey = (args.flags["to-pubkey"] as string) || addr.publicKey;
  const client = new Client(s.serverUrl, s.token);

  let resp;
  if (pubkey) {
    const ct = await seal(text, pubkey); // encrypt on THIS machine
    resp = await client.send({ to: addr.sessionId, text: ct, enc: "box1" });
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
    resp = await client.send({ to: addr.sessionId, text });
  }
  emit({ msg_id: resp.msg_id, seq: resp.seq, encrypted: !!pubkey });
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

async function cmdReceive(args: ReturnType<typeof parseArgs>, store: SessionStore): Promise<number> {
  const s = loadSessionOrExit(store);
  const client = new Client(s.serverUrl, s.token);
  const after = args.flags.after !== undefined ? parseInt(String(args.flags.after), 10) : 0;

  const page = await client.inboxPage(after);
  const messages = await Promise.all(
    page.messages.map(async (m) => {
      const d = await decryptOne(m, s);
      return { seq: m.seq, msg_id: m.msg_id, from: m.from, ...d, attachments: m.attachments };
    }),
  );
  if (args.flags.ack && page.messages.length > 0) {
    await client.ack(page.messages[page.messages.length - 1].seq);
  }
  emit({ messages, cursor: page.cursor, next_cursor: page.next_cursor, has_more: page.has_more });
  return 0;
}

async function cmdSubscribe(args: ReturnType<typeof parseArgs>, store: SessionStore): Promise<number> {
  const s = loadSessionOrExit(store);
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
