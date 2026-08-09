// Per-home store of shared-context symmetric keys. These decrypt whole shared
// documents, so the file is owner-only — the same treatment session.json gets.
import { mkdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { atomicWritePrivate } from "./installation.js";

interface KeyFile {
  keys: Record<string, string>;
}

/** True for a value that is a plausible KeyFile: a non-null, non-array object
 *  whose `keys` is itself a non-null object. Anything else — including valid
 *  JSON of the wrong shape, like `null` or `{}` — is treated as corrupt. */
function isKeyFile(v: unknown): v is KeyFile {
  if (typeof v !== "object" || v === null || Array.isArray(v)) return false;
  const keys = (v as Record<string, unknown>).keys;
  return typeof keys === "object" && keys !== null && !Array.isArray(keys);
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

  get(contextID: string): string | undefined {
    return this.load().keys[contextID];
  }

  list(): string[] {
    return Object.keys(this.load().keys);
  }

  save(contextID: string, keyB64: string): void {
    const data = this.load();
    data.keys[contextID] = keyB64;
    mkdirSync(this.home, { recursive: true, mode: 0o700 });
    atomicWritePrivate(this.file, JSON.stringify(data, null, 2));
  }
}
