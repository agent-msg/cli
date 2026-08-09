// Per-home store of shared-context symmetric keys. These decrypt whole shared
// documents, so the file is owner-only — the same treatment session.json gets.
import { mkdirSync, readFileSync, writeFileSync, chmodSync } from "node:fs";
import { join } from "node:path";

interface KeyFile {
  keys: Record<string, string>;
}

export class ContextKeys {
  private file: string;
  constructor(private home: string) {
    this.file = join(home, "contexts.json");
  }

  private load(): KeyFile {
    try {
      return JSON.parse(readFileSync(this.file, "utf8")) as KeyFile;
    } catch {
      return { keys: {} };
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
    writeFileSync(this.file, JSON.stringify(data, null, 2), { mode: 0o600 });
    chmodSync(this.file, 0o600); // enforce even if the file pre-existed
  }
}
