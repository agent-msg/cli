import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtempSync, rmSync, statSync, mkdirSync, writeFileSync, chmodSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ContextKeys } from "../src/context.js";
import { decryptSym, encryptSym, seal, open, generateContextKey, generateKeypair } from "../src/crypto.js";
import { InstallationStore } from "../src/installation.js";
import { installationBoxKeys } from "../src/installation-box.js";
import { Contacts } from "../src/contacts.js";

let home: string;
beforeEach(() => (home = mkdtempSync(join(tmpdir(), "amsg-ctx-"))));
afterEach(() => rmSync(home, { recursive: true, force: true }));

import { createServer, Server } from "node:http";
import { vi } from "vitest";
import { run } from "../src/cli.js";

let server: Server, base: string;
let ctxVersion = 0;
let ctxEpoch = 1;
let lastNameEnc = "";
// Test-controlled fixtures for the new pending/keys/get-content endpoints.
let ctxSealedKey = ""; // sealed_key returned by GET /v1/contexts/c1
let ctxDownloadContent = ""; // ciphertext served at /download-content
let ctxHasContent = false;
let pendingList: unknown[] = [];
let uploadedEnvelopes: { context_id: string; envelopes: { recipient_installation: string; sealed_key: string }[] }[] = [];
let removedMembers: string[] = [];
let addedMembers: { github_user_id: string; role: string; recipient_installation: string; sealed_key: string }[] = [];

beforeEach(async () => {
  ctxVersion = 0;
  ctxEpoch = 1;
  lastNameEnc = "";
  ctxSealedKey = "";
  ctxDownloadContent = "";
  ctxHasContent = false;
  pendingList = [];
  uploadedEnvelopes = [];
  removedMembers = [];
  addedMembers = [];
  server = createServer((req, res) => {
    let b = "";
    req.on("data", (c) => (b += c));
    req.on("end", () => {
      // The /upload PUT carries binary ciphertext, not JSON — parsing it
      // unconditionally would crash this handler and hang the request.
      let body: any = {};
      try {
        body = b ? JSON.parse(b) : {};
      } catch {
        body = {};
      }
      res.setHeader("Content-Type", "application/json");
      if (req.url === "/v1/register") {
        return res.end(JSON.stringify({ session_id: "s1", token: "t1", github_login: "u", github_user_id: "1" }));
      }
      if (req.url === "/v1/whoami/card" && req.method === "GET") {
        return res.end(JSON.stringify({
          version: 1, service: "agentmsg", identity_type: "github", principal_id: "1",
          installation_id: "install-self", session_id: "s1", verified: true,
          public_key: "", signature: "", github_user_id: "1", github_login: "u",
        }));
      }
      if (req.url === "/v1/contexts" && req.method === "POST") {
        lastNameEnc = String(body.name_enc ?? "");
        ctxEpoch = 1;
        return res.end(JSON.stringify({ id: "c1", name_enc: body.name_enc, owner_uid: "1", epoch: ctxEpoch, version: 0, bytes: 0, updated_at: "", role: "owner" }));
      }
      if (req.url === "/v1/contexts" && req.method === "GET") {
        return res.end(JSON.stringify([{ id: "c1", name_enc: lastNameEnc, owner_uid: "1", epoch: ctxEpoch, version: ctxVersion, bytes: ctxHasContent ? 1 : 0, updated_at: "", role: "owner" }]));
      }
      if (req.url === "/v1/contexts/pending" && req.method === "GET") {
        return res.end(JSON.stringify(pendingList));
      }
      if (req.url === "/v1/contexts/c1/keys" && req.method === "POST") {
        uploadedEnvelopes.push({ context_id: "c1", envelopes: body.envelopes || [] });
        return res.end(JSON.stringify({ status: "stored" }));
      }
      if (req.url === "/v1/contexts/c1/members" && req.method === "POST") {
        addedMembers.push({
          github_user_id: String(body.github_user_id ?? ""), role: String(body.role ?? ""),
          recipient_installation: String(body.recipient_installation ?? ""),
          sealed_key: String(body.sealed_key ?? ""),
        });
        return res.end(JSON.stringify({ status: "added" }));
      }
      if (req.url?.startsWith("/v1/contexts/c1/members/") && req.method === "DELETE") {
        removedMembers.push(decodeURIComponent(req.url.slice("/v1/contexts/c1/members/".length)));
        ctxEpoch++;
        return res.end(JSON.stringify({ id: "c1", name_enc: "", owner_uid: "1", epoch: ctxEpoch, version: ctxVersion, bytes: ctxHasContent ? 1 : 0, updated_at: "", role: "owner" }));
      }
      if (req.url === "/v1/contexts/c1" && req.method === "GET") {
        return res.end(JSON.stringify({
          id: "c1", name_enc: "", owner_uid: "1", epoch: ctxEpoch, version: ctxVersion,
          bytes: ctxHasContent ? 1 : 0, updated_at: "", role: "owner",
          download_url: ctxHasContent ? base + "/download-content" : undefined,
          sealed_key: ctxSealedKey || undefined,
        }));
      }
      if (req.url === "/download-content" && req.method === "GET") {
        return res.end(ctxDownloadContent);
      }
      if (req.url === "/v1/contexts/c1" && req.method === "PUT") {
        return res.end(JSON.stringify({ upload_url: base + "/upload", blob_key: "k" }));
      }
      if (req.url === "/upload") {
        ctxDownloadContent = b;
        ctxHasContent = true;
        return res.end("{}");
      }
      if (req.url === "/v1/contexts/c1/commit") {
        if (body.expected_version !== ctxVersion) {
          res.statusCode = 409;
          return res.end(JSON.stringify({ error: "version_conflict", current_version: ctxVersion }));
        }
        ctxVersion++;
        return res.end(JSON.stringify({ id: "c1", name_enc: "", owner_uid: "1", epoch: ctxEpoch, version: ctxVersion, bytes: 0, updated_at: "", role: "owner" }));
      }
      res.end("{}");
    });
  });
  await new Promise<void>((r) => server.listen(0, r));
  const a = server.address();
  base = `http://127.0.0.1:${typeof a === "object" && a ? a.port : 0}`;
});
afterEach(() => new Promise<void>((r) => server.close(() => r())));

async function cli(...argv: string[]) {
  process.env.AGENTMSG_HOME = home;
  process.env.AGENTMSG_SERVER = base;
  delete process.env.AGENTMSG_PROFILE;
  const code = await run(argv);
  delete process.env.AGENTMSG_HOME;
  delete process.env.AGENTMSG_SERVER;
  return code;
}

describe("agentmsg context", () => {
  it("creates a context and saves its key locally", async () => {
    expect(await cli("register", "--dev-user", "9", "--allow-insecure-http")).toBe(0);
    const out: string[] = [];
    const spy = vi.spyOn(process.stdout, "write").mockImplementation((c: any) => (out.push(String(c)), true));
    const code = await cli("context", "create", "--name", "team notes");
    spy.mockRestore();

    expect(code).toBe(0);
    const savedKey = new ContextKeys(home).get("c1");
    expect(savedKey).toBeTruthy(); // key stored for later reads
    expect(out.join("")).not.toContain("team notes"); // the CLI doesn't print it

    // The actual product promise: the server must never receive the plaintext
    // name. Proving stdout is clean isn't enough — prove what left the machine
    // was neither the plaintext nor some other garbage, but genuinely the
    // ciphertext of "team notes" under the key that got saved locally.
    expect(lastNameEnc).not.toBe("team notes");
    expect(lastNameEnc).not.toContain("team notes");
    expect(await decryptSym(lastNameEnc, savedKey!)).toBe("team notes");
  });

  // Conflicts are the normal path, so the CLI must surface everything the
  // agent needs to merge instead of just failing.
  it("reports a conflict with the data needed to merge", async () => {
    expect(await cli("register", "--dev-user", "9", "--allow-insecure-http")).toBe(0);
    await cli("context", "create", "--name", "n");
    ctxVersion = 5; // someone else moved it while we were editing

    const errs: string[] = [];
    const spy = vi.spyOn(process.stderr, "write").mockImplementation((c: any) => (errs.push(String(c)), true));
    const code = await cli("context", "set", "--id", "c1", "--text", "mine", "--expect", "0");
    spy.mockRestore();

    expect(code).not.toBe(0);
    const msg = errs.join("");
    expect(msg).toMatch(/version_conflict|conflict/i);
    expect(msg).toContain("5");           // the version we must rebase onto
    expect(msg).toMatch(/context get/);   // tells the agent how to fetch it
  });

  // R4(a) — the receive side that was missing entirely: a context whose key
  // is absent locally but present as a `sealed_key` envelope on the server
  // must be imported (opened with the installation-derived X25519 private
  // key) and saved, so the content can actually be decrypted.
  it("imports a sealed_key envelope on get when no local key exists, and decrypts", async () => {
    expect(await cli("register", "--dev-user", "9", "--allow-insecure-http")).toBe(0);

    // No local key for c1: simulate this by never calling `context create`
    // and instead seeding a sealed_key envelope for THIS installation.
    const installation = new InstallationStore(home).loadOrCreate();
    const boxKeys = installationBoxKeys(installation.seed);
    const contextKey = await generateContextKey();
    ctxSealedKey = await seal(contextKey, boxKeys.publicKey);
    ctxDownloadContent = await encryptSym("secret plan", contextKey);
    ctxHasContent = true;

    expect(new ContextKeys(home).get("c1")).toBeUndefined(); // precondition

    const out: string[] = [];
    const spy = vi.spyOn(process.stdout, "write").mockImplementation((c: any) => (out.push(String(c)), true));
    const code = await cli("context", "get", "--id", "c1");
    spy.mockRestore();

    expect(code).toBe(0);
    expect(JSON.parse(out.join(""))).toMatchObject({ context_id: "c1", text: "secret plan" });
    // The imported key must now be saved locally, for next time.
    expect(new ContextKeys(home).get("c1")).toBe(contextKey);
  });

  // Critical A (review fix): ContextKeys had no notion of epoch, so a
  // locally cached key was trusted forever — even after a real rotation
  // (revoke) moved the server past it. A legitimate remaining member would
  // then be permanently unable to read anything written after the
  // rotation, with no command able to recover. The fix: compare the local
  // key's epoch against the server's current one on every read, and
  // discard + re-import from `sealed_key` when they differ.
  it("discards a stale local key and re-imports when the server has moved to a newer epoch", async () => {
    expect(await cli("register", "--dev-user", "9", "--allow-insecure-http")).toBe(0);
    await cli("context", "create", "--name", "n");
    const staleKey = new ContextKeys(home).get("c1")!;

    // Simulate the server having rotated to epoch 2 (e.g. another member ran
    // `revoke`) while this session was away: a fresh key sealed to OUR
    // installation, and content re-encrypted under it.
    const installation = new InstallationStore(home).loadOrCreate();
    const boxKeys = installationBoxKeys(installation.seed);
    const freshKey = await generateContextKey();
    ctxEpoch = 2;
    ctxSealedKey = await seal(freshKey, boxKeys.publicKey);
    ctxDownloadContent = await encryptSym("post-rotation content", freshKey);
    ctxHasContent = true;

    const out: string[] = [];
    const spy = vi.spyOn(process.stdout, "write").mockImplementation((c: any) => (out.push(String(c)), true));
    const code = await cli("context", "get", "--id", "c1");
    spy.mockRestore();

    expect(code).toBe(0);
    expect(JSON.parse(out.join(""))).toMatchObject({ context_id: "c1", epoch: 2, text: "post-rotation content" });
    const newLocalKey = new ContextKeys(home).get("c1");
    expect(newLocalKey).toBe(freshKey);
    expect(newLocalKey).not.toBe(staleKey);
  });

  it("gives a clear message (not a raw exception) when a stale key cannot be re-imported", async () => {
    expect(await cli("register", "--dev-user", "9", "--allow-insecure-http")).toBe(0);
    await cli("context", "create", "--name", "n");
    // Rotated elsewhere, but no envelope has reached us yet.
    ctxEpoch = 2;
    ctxSealedKey = "";

    const errs: string[] = [];
    const spy = vi.spyOn(process.stderr, "write").mockImplementation((c: any) => (errs.push(String(c)), true));
    const code = await cli("context", "get", "--id", "c1");
    spy.mockRestore();

    expect(code).toBe(1);
    expect(errs.join("")).toMatch(/older epoch/i);
  });

  it("gives a clear message instead of an uncaught exception when content fails to decrypt", async () => {
    expect(await cli("register", "--dev-user", "9", "--allow-insecure-http")).toBe(0);
    await cli("context", "create", "--name", "n");
    // Epoch matches (so the key looks fresh) but the actual bytes on the
    // "server" were encrypted under a different key — e.g. a partial
    // rotation failure. `get` must not let decryptSym's raw exception
    // through.
    ctxHasContent = true;
    ctxDownloadContent = await encryptSym("secret", await generateContextKey());

    const errs: string[] = [];
    const spy = vi.spyOn(process.stderr, "write").mockImplementation((c: any) => (errs.push(String(c)), true));
    const code = await cli("context", "get", "--id", "c1");
    spy.mockRestore();

    expect(code).toBe(1);
    expect(errs.join("")).toMatch(/could not decrypt/i);
  });

  // R4(b) — piggyback answering: any context command should, in passing,
  // answer outstanding pending authorisations it can — no daemon, no new
  // command, riding on a call the agent already makes.
  it("answers a pending authorisation in passing when running an ordinary command", async () => {
    expect(await cli("register", "--dev-user", "9", "--allow-insecure-http")).toBe(0);
    await cli("context", "create", "--name", "n"); // we now hold c1's key locally
    const ourKey = new ContextKeys(home).get("c1")!;

    // Bob is a known contact on a genuinely DIFFERENT installation: derive
    // his box key from a distinct seed, exactly as a real second machine
    // would, and give him an unrelated session messaging keypair too — the
    // whole point of R4b is that these are NOT interchangeable. Sealing to
    // bob's messaging key (as the pre-fix code did) would produce an
    // envelope his installation box private key could never open; a test
    // that fabricated one keypair and used it for both roles would never
    // have caught that.
    const bobSeed = Buffer.alloc(32, 0x42);
    const bobBoxKeys = installationBoxKeys(bobSeed);
    const bobSessionKeys = await generateKeypair();
    new Contacts(home).add("bob", {
      sessionId: "s-bob", publicKey: bobSessionKeys.publicKey, githubUserId: "42",
      installationBoxKey: bobBoxKeys.publicKey,
    });
    pendingList = [{ context_id: "c1", epoch: 1, github_user_id: "42", role: "writer", recipient_installation: "install-bob" }];

    const code = await cli("context", "list"); // an ordinary command, not a new one
    expect(code).toBe(0);

    expect(uploadedEnvelopes).toHaveLength(1);
    expect(uploadedEnvelopes[0].context_id).toBe("c1");
    expect(uploadedEnvelopes[0].envelopes).toHaveLength(1);
    const envelope = uploadedEnvelopes[0].envelopes[0];
    expect(envelope.recipient_installation).toBe("install-bob");
    // Prove it is genuinely usable by Bob on HIS machine: his installation
    // box private key (derived independently from his own seed, never
    // shared with the sealer) opens it, and it is the real context key.
    const opened = await open(envelope.sealed_key, bobBoxKeys.publicKey, bobBoxKeys.privateKey);
    expect(opened).toBe(ourKey);
    // Negative pin: bob's SESSION messaging key must NOT be able to open it
    // — sealing to the wrong key type must fail, not silently "work".
    await expect(open(envelope.sealed_key, bobSessionKeys.publicKey, bobSessionKeys.privateKey)).rejects.toThrow();
  });

  // R4b: 'share' must seal to the recipient's INSTALLATION box key, derived
  // from a genuinely different installation seed — the way a real second
  // machine's key actually comes into being — not to a keypair fabricated
  // once and reused for both sealing and opening (that anti-pattern is
  // exactly what let the original bug ship: sealing to contact.publicKey,
  // the recipient's ephemeral SESSION messaging key, produced an envelope
  // their installation box private key could never open).
  it("share seals to the recipient's installation box key, openable only by that installation's derived private key", async () => {
    expect(await cli("register", "--dev-user", "9", "--allow-insecure-http")).toBe(0);
    await cli("context", "create", "--name", "n");
    const ourKey = new ContextKeys(home).get("c1")!;

    // Alice's installation lives on a wholly separate seed from ours.
    const aliceSeed = Buffer.alloc(32, 0x99);
    const aliceBoxKeys = installationBoxKeys(aliceSeed);
    const aliceSessionKeys = await generateKeypair(); // her unrelated messaging keypair
    new Contacts(home).add("alice", {
      sessionId: "s-alice", publicKey: aliceSessionKeys.publicKey, githubUserId: "7",
      installationBoxKey: aliceBoxKeys.publicKey,
    });

    const code = await cli("context", "share", "--id", "c1", "--to", "alice");
    expect(code).toBe(0);

    expect(addedMembers).toHaveLength(1);
    expect(addedMembers[0].github_user_id).toBe("7");
    // The envelope is genuinely usable on Alice's machine: her installation
    // box private key (derived independently, from HER seed) opens it.
    const opened = await open(addedMembers[0].sealed_key, aliceBoxKeys.publicKey, aliceBoxKeys.privateKey);
    expect(opened).toBe(ourKey);
    // Negative pin: sealing to the SESSION public key and trying to open
    // with the installation box private key must fail — that is precisely
    // the distinction the original bug violated.
    const wrongSeal = await seal(ourKey, aliceSessionKeys.publicKey);
    await expect(open(wrongSeal, aliceBoxKeys.publicKey, aliceBoxKeys.privateKey)).rejects.toThrow();
  });

  it("share refuses (with a clear message, not a crash) when the contact predates installation keys", async () => {
    expect(await cli("register", "--dev-user", "9", "--allow-insecure-http")).toBe(0);
    await cli("context", "create", "--name", "n");
    // A contact saved before R4b has no installationBoxKey on disk.
    new Contacts(home).add("alice", {
      sessionId: "s-alice", publicKey: (await generateKeypair()).publicKey, githubUserId: "7",
      installationBoxKey: "",
    });

    const errs: string[] = [];
    const spy = vi.spyOn(process.stderr, "write").mockImplementation((c: any) => (errs.push(String(c)), true));
    const code = await cli("context", "share", "--id", "c1", "--to", "alice");
    spy.mockRestore();

    expect(code).toBe(1);
    expect(errs.join("")).toMatch(/predates installation keys/i);
    expect(addedMembers).toHaveLength(0);
  });

  it("never lets a failed pending-answer break the command the user asked for", async () => {
    expect(await cli("register", "--dev-user", "9", "--allow-insecure-http")).toBe(0);
    await cli("context", "create", "--name", "n");
    // A malformed pending entry (missing recipient_installation) must not
    // crash the actual command.
    pendingList = [{ context_id: "c1", epoch: 1, github_user_id: "42", role: "writer" }];
    const code = await cli("context", "list");
    expect(code).toBe(0);
  });

  describe("revoke", () => {
    // R4(c) — honest revoke: when the owner holds the key locally, revoke
    // must actually rotate it (fresh key, re-encrypted content, sealed to
    // the owner's own installation so future reads work) and only THEN may
    // it claim any protection.
    it("rotates the key for real and re-encrypts existing content", async () => {
      expect(await cli("register", "--dev-user", "9", "--allow-insecure-http")).toBe(0);
      await cli("context", "create", "--name", "n");
      await cli("context", "set", "--id", "c1", "--text", "hello", "--expect", "0");
      const oldKey = new ContextKeys(home).get("c1")!;

      const out: string[] = [];
      const spy = vi.spyOn(process.stdout, "write").mockImplementation((c: any) => (out.push(String(c)), true));
      const errs: string[] = [];
      const espy = vi.spyOn(process.stderr, "write").mockImplementation((c: any) => (errs.push(String(c)), true));
      const code = await cli("context", "revoke", "--id", "c1", "--user", "99");
      spy.mockRestore();
      espy.mockRestore();

      expect(code).toBe(0);
      expect(removedMembers).toContain("99");
      const newKey = new ContextKeys(home).get("c1")!;
      expect(newKey).not.toBe(oldKey); // genuinely rotated, not the same key relabelled

      // The claim printed must be true: it only appears because rotation ran.
      const msg = errs.join("");
      expect(msg).toMatch(/no longer decrypts|rotated/i);

      // The content on the "server" is now under the NEW key, not the old one.
      expect(await decryptSym(ctxDownloadContent, newKey)).toBe("hello");
      await expect(decryptSym(ctxDownloadContent, oldKey)).rejects.toThrow();

      // We uploaded a self-addressed envelope for the new epoch so we can
      // still read our own context after rotating.
      expect(uploadedEnvelopes.length).toBeGreaterThan(0);
    });

    // The hard requirement: a false security promise is worse than a missing
    // feature. If rotation cannot run (no local key to re-encrypt with), the
    // CLI must not claim any protection it did not deliver.
    it("prints no protection claim when it cannot rotate", async () => {
      expect(await cli("register", "--dev-user", "9", "--allow-insecure-http")).toBe(0);
      // A context we have no local key for at all (never created/imported
      // here, and no sealed_key available to import either).
      const errs: string[] = [];
      const espy = vi.spyOn(process.stderr, "write").mockImplementation((c: any) => (errs.push(String(c)), true));
      const code = await cli("context", "revoke", "--id", "c1", "--user", "99");
      espy.mockRestore();

      expect(code).toBe(0);
      expect(removedMembers).toContain("99");
      const msg = errs.join("");
      expect(msg).not.toMatch(/protects|no longer decrypts|rotated/i);
    });
  });
});

describe("ContextKeys", () => {
  it("round-trips a key", () => {
    const k = new ContextKeys(home);
    k.save("ctx1", "base64key");
    expect(k.get("ctx1")).toBe("base64key");
  });

  it("returns undefined for an unknown context", () => {
    expect(new ContextKeys(home).get("nope")).toBeUndefined();
  });

  it("persists across instances", () => {
    new ContextKeys(home).save("ctx1", "key1");
    expect(new ContextKeys(home).get("ctx1")).toBe("key1");
  });

  // The file holds decryption keys for shared documents; group- or
  // world-readable would expose every context on a shared machine.
  it("stores keys with owner-only permissions", () => {
    const k = new ContextKeys(home);
    k.save("ctx1", "key1");
    expect(statSync(join(home, "contexts.json")).mode & 0o077).toBe(0);
  });

  it("lists saved context ids", () => {
    const k = new ContextKeys(home);
    k.save("a", "1");
    k.save("b", "2");
    expect(k.list().sort()).toEqual(["a", "b"]);
  });

  // A file that is valid JSON but the wrong shape must be treated the same
  // as a corrupt/missing one, not crash the caller.
  it("treats a JSON `null` file as empty", () => {
    mkdirSync(home, { recursive: true });
    writeFileSync(join(home, "contexts.json"), "null");
    expect(new ContextKeys(home).get("ctx1")).toBeUndefined();
  });

  it("treats a JSON `{}` file as empty and can still save into it", () => {
    mkdirSync(home, { recursive: true });
    writeFileSync(join(home, "contexts.json"), "{}");
    const k = new ContextKeys(home);
    expect(() => k.save("ctx1", "key1")).not.toThrow();
    expect(k.get("ctx1")).toBe("key1");
  });

  // Enforces the mode even when contexts.json already existed with looser
  // permissions before save() ran — writeFileSync/atomicWritePrivate must not
  // silently inherit stale permissions from a pre-existing file.
  it("tightens permissions on a pre-existing, loosely-permissioned file", () => {
    mkdirSync(home, { recursive: true });
    const file = join(home, "contexts.json");
    writeFileSync(file, JSON.stringify({ keys: {} }));
    chmodSync(file, 0o644);
    const k = new ContextKeys(home);
    k.save("ctx1", "key1");
    expect(statSync(file).mode & 0o077).toBe(0);
  });
});
