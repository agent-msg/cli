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
    try {
      return JSON.parse(raw) as Record<string, Address>;
    } catch {
      throw new Error(`contacts file is corrupt: ${this.file}`);
    }
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
    return { sessionId: nameOrSid, publicKey: "", githubUserId: "" };
  }

  list(): NamedAddress[] {
    const all = this.read();
    return Object.entries(all).map(([name, a]) => ({ name, ...a }));
  }
}
