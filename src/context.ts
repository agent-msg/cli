// Per-home store of shared-context symmetric keys. These decrypt whole shared
// documents, so the file is owner-only — the same treatment session.json gets.
import { mkdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { atomicWritePrivate } from "./installation.js";

export interface KeyEntry {
  key: string;
  /** The epoch this key is valid for. Undefined means "unknown" — either a
   *  key saved before epoch tracking existed (a plain-string legacy entry)
   *  or a save() call that didn't pass one. Callers must treat "unknown" as
   *  potentially stale, never as confirmed-current: trusting a key of
   *  unknown vintage forever is exactly the bug this type exists to close
   *  (a real `context revoke` rotation left remaining members permanently
   *  unable to decrypt anything written afterward, with no local signal
   *  that their cached key had gone stale). */
  epoch?: number;
}

interface KeyFile {
  keys: Record<string, KeyEntry | string>;
}

/** True for a value that is a plausible KeyFile: a non-null, non-array object
 *  whose `keys` is itself a non-null object. Anything else — including valid
 *  JSON of the wrong shape, like `null` or `{}` — is treated as corrupt. */
function isKeyFile(v: unknown): v is KeyFile {
  if (typeof v !== "object" || v === null || Array.isArray(v)) return false;
  const keys = (v as Record<string, unknown>).keys;
  return typeof keys === "object" && keys !== null && !Array.isArray(keys);
}

/** Accepts both the current object shape and the pre-epoch-tracking plain
 *  string shape, so an existing contexts.json on disk keeps working without
 *  a migration step. A string entry's epoch is always "unknown". */
function normalizeEntry(v: KeyEntry | string | undefined): KeyEntry | undefined {
  if (v === undefined) return undefined;
  if (typeof v === "string") return { key: v, epoch: undefined };
  if (typeof v === "object" && v !== null && typeof v.key === "string") {
    return { key: v.key, epoch: typeof v.epoch === "number" ? v.epoch : undefined };
  }
  return undefined; // corrupt entry — treated the same as absent
}

export class ContextKeys {
  private file: string;
  constructor(private home: string) {
    this.file = join(home, "contexts.json");
  }

  private load(): KeyFile {
    try {
      const parsed: unknown = JSON.parse(readFileSync(this.file, "utf8"));
      return isKeyFile(parsed) ? parsed : { keys: {} };
    } catch {
      return { keys: {} }; // missing, unreadable, or not valid JSON
    }
  }

  /** The raw key string, regardless of which epoch it belongs to. Most
   *  callers that actually use the key to decrypt something should prefer
   *  getEntry() so they can check it against the server's current epoch
   *  first — see KeyEntry's doc comment for why. */
  get(contextID: string): string | undefined {
    return normalizeEntry(this.load().keys[contextID])?.key;
  }

  /** The key plus the epoch it is valid for (epoch undefined = unknown /
   *  pre-epoch-tracking). */
  getEntry(contextID: string): KeyEntry | undefined {
    return normalizeEntry(this.load().keys[contextID]);
  }

  list(): string[] {
    return Object.keys(this.load().keys);
  }

  /** epoch is optional only for backward compatibility with existing
   *  callers/tests; new code should always pass the epoch the key was
   *  actually issued for. Omitting it stores "unknown", which downstream
   *  reads always treat as needing a freshness check against the server. */
  save(contextID: string, keyB64: string, epoch?: number): void {
    const data = this.load();
    data.keys[contextID] = { key: keyB64, epoch };
    mkdirSync(this.home, { recursive: true, mode: 0o700 });
    atomicWritePrivate(this.file, JSON.stringify(data, null, 2));
  }
}
