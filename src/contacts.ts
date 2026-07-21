// Local address book: maps a friendly name to a peer's address card
// (session id + public key), exchanged out-of-band. Lets `send --to <name>`
// encrypt by default. Stored in AGENTMSG_HOME/contacts.json.
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
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

export class Contacts {
  private file: string;
  constructor(private home: string = defaultHome()) {
    this.file = join(home, "contacts.json");
  }

  private read(): Record<string, Address> {
    try {
      return JSON.parse(readFileSync(this.file, "utf8")) as Record<string, Address>;
    } catch {
      return {};
    }
  }

  add(name: string, addr: Address): void {
    const all = this.read();
    all[name] = addr;
    mkdirSync(this.home, { recursive: true, mode: 0o700 });
    writeFileSync(this.file, JSON.stringify(all, null, 2), { mode: 0o600 });
  }

  /**
   * Resolve a --to argument: a saved contact name wins; otherwise the argument
   * is treated as a raw session id with no known public key (send falls back to
   * plaintext). Returns null only for the empty string.
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
