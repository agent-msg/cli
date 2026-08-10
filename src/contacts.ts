// Local address book: maps a friendly name to a peer's address card
// (session id + public key), exchanged out-of-band. Lets `send --to <name>`
// encrypt by default. Stored in AGENTMSG_HOME/contacts.json.
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { join } from "node:path";
import { defaultHome } from "./session.js";

export interface Address {
  sessionId: string;
  publicKey: string;
  githubUserId: string;
  // installationBoxKey is the contact's installation-derived X25519 public
  // key (see installation-box.ts) — the key shared-context envelopes must be
  // sealed to. Deliberately kept separate from publicKey (that contact's
  // ephemeral per-session messaging keypair, used for direct-message
  // seal/open): sealing a context key to publicKey produces an envelope the
  // recipient's context code can never open — see R4b. Empty for contacts
  // saved before this field existed, or from a peer whose card predates it.
  installationBoxKey: string;
  // installationId is the contact's INSTALLATION id (stable across all of
  // their sessions on that machine) — this is what `addContextMember` must
  // be given as the recipient. It matches how the server stores
  // ContextMember.RecipientInstallation and how the recipient's own read
  // path looks envelopes up (sess.InstallationID). Deliberately distinct
  // from BOTH sessionId (a session, not the machine) and installationBoxKey
  // (the sealing key, not the id used to address the envelope): addressing
  // by session id stores the envelope under a value the recipient's session
  // never matches, so sealed_key is never returned to them — and the
  // server's handleListPendingContextKeys treats the member as already
  // answered the moment ANY envelope exists under that (wrong) key, leaving
  // the recipient permanently stuck with no recovery path. Empty for
  // contacts saved before this field existed, or from a peer whose card
  // predates installation identity — callers must refuse to share rather
  // than fall back to sessionId (see cli.ts context share).
  installationId: string;
}

export interface NamedAddress extends Address {
  name: string;
}

/**
 * A short, human-verifiable fingerprint of a public key (SEC-05). Two people can
 * compare this out-of-band to confirm they saved the same key.
 */
export function fingerprint(publicKeyB64: string): string {
  const hex = createHash("sha256").update(publicKeyB64).digest("hex").slice(0, 16);
  return (hex.match(/.{4}/g) || []).join("-"); // e.g. 1a2b-3c4d-5e6f-7a8b
}

export class Contacts {
  private file: string;
  constructor(private home: string = defaultHome()) {
    this.file = join(home, "contacts.json");
  }

  // Reads the book. A missing file is an empty book; ANY other error (corrupt
  // JSON, bad permissions, I/O) is surfaced — never silently treated as "no
  // contacts", which would push a send onto the unencrypted path (SEC-04).
  private read(): Record<string, Address> {
    let raw: string;
    try {
      raw = readFileSync(this.file, "utf8");
    } catch (e) {
      if ((e as NodeJS.ErrnoException).code === "ENOENT") return {};
      throw new Error(`cannot read contacts (${(e as Error).message})`);
    }
    let parsed: Record<string, Partial<Address>>;
    try {
      parsed = JSON.parse(raw) as Record<string, Partial<Address>>;
    } catch {
      throw new Error(`contacts file is corrupt: ${this.file}`);
    }
    // A contact saved before installationBoxKey/installationId existed
    // simply lacks the field on disk; default each to "" rather than
    // leaving it `undefined`, so every caller can treat "not known"
    // uniformly (see each field's doc).
    const out: Record<string, Address> = {};
    for (const [name, a] of Object.entries(parsed)) {
      out[name] = {
        sessionId: a.sessionId || "",
        publicKey: a.publicKey || "",
        githubUserId: a.githubUserId || "",
        installationBoxKey: a.installationBoxKey || "",
        installationId: a.installationId || "",
      };
    }
    return out;
  }

  /**
   * Save a contact. Trust-on-first-use: if the name already exists with a
   * DIFFERENT public key, refuse unless force is set — a silently changed key is
   * how an attacker would redirect your encryption (SEC-05).
   */
  add(name: string, addr: Address, force = false): void {
    const all = this.read();
    const prev = all[name];
    if (prev && prev.publicKey !== addr.publicKey && !force) {
      throw new Error(
        `contact "${name}" already has a different public key (fingerprint ${fingerprint(prev.publicKey)}). ` +
          `Verify the new key out-of-band, then re-run with --force to replace it.`,
      );
    }
    all[name] = addr;
    mkdirSync(this.home, { recursive: true, mode: 0o700 });
    writeFileSync(this.file, JSON.stringify(all, null, 2), { mode: 0o600 });
  }

  /**
   * Resolve a --to argument: a saved contact name wins; otherwise the argument
   * is treated as a raw session id with no known public key (the caller decides
   * whether to allow an unencrypted send). Returns null only for the empty
   * string.
   */
  resolve(nameOrSid: string): Address | null {
    if (!nameOrSid) return null;
    const saved = this.read()[nameOrSid];
    if (saved) return saved;
    return { sessionId: nameOrSid, publicKey: "", githubUserId: "", installationBoxKey: "", installationId: "" };
  }

  list(): NamedAddress[] {
    const all = this.read();
    return Object.entries(all).map(([name, a]) => ({ name, ...a }));
  }
}
