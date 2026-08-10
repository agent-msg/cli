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
// Fixture for GET /v1/contexts/c1/members — the server's own, always-current
// record of each member's installation id + PUBLIC box key. Tests set this
// directly to control what the "server" reports, independently of whatever
// (possibly stale, possibly absent) entry exists in the local contact book.
let membersList: unknown[] = [];
let uploadedEnvelopes: { context_id: string; envelopes: { recipient_installation: string; sealed_key: string }[] }[] = [];
let removedMembers: string[] = [];
let addedMembers: { github_user_id: string; role: string; recipient_installation: string; sealed_key: string }[] = [];
// The role the fake server reports for the calling user on context c1.
// Defaults to "owner" (as a real creator would see); tests that need to
// exercise the export-recovery owner-only check flip this to something else.
let ctxRole = "owner";
// Every raw request body this fake server ever received, in order. Used to
// prove a value (like a recovery code) genuinely never left the machine —
// checking stdout/stderr is not sufficient, only the wire is.
let allRequestBodies: string[] = [];
// Counts /v1/register calls with a non-default credential, so distinct
// identities registering against this fake server get distinct
// session/installation ids (see the /v1/register handler below).
let registerCount = 0;

beforeEach(async () => {
  ctxVersion = 0;
  ctxEpoch = 1;
  lastNameEnc = "";
  ctxSealedKey = "";
  ctxDownloadContent = "";
  ctxHasContent = false;
  pendingList = [];
  membersList = [];
  uploadedEnvelopes = [];
  removedMembers = [];
  addedMembers = [];
  ctxRole = "owner";
  allRequestBodies = [];
  registerCount = 0;
  server = createServer((req, res) => {
    let b = "";
    req.on("data", (c) => (b += c));
    req.on("end", () => {
      allRequestBodies.push(b);
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
        // Mirrors the real handleRegister (api.go): every registration binds
        // a real installation and the response now carries installation_id
        // (the R8 fix). The default dev-user credential "9" keeps the
        // long-standing session_id/installation_id/github_user_id the rest
        // of this file's tests were written against; any other credential
        // (used by the identity-round-trip test below, to model a genuinely
        // separate person/machine registering) gets its own distinct triple,
        // the same way two real registrations against the real server would.
        const credential = String(body.credential ?? "");
        registerCount++;
        if (credential === "9") {
          return res.end(JSON.stringify({
            session_id: "s1", token: "t1", github_login: "u", github_user_id: "1",
            installation_id: "install-self",
          }));
        }
        return res.end(JSON.stringify({
          session_id: `s-reg${registerCount}`, token: `t-reg${registerCount}`,
          github_login: `user${registerCount}`, github_user_id: `${1000 + registerCount}`,
          installation_id: `install-reg${registerCount}`,
        }));
      }
      // The real server's handleAddressCard (api_verified.go) 404s with
      // address_card_unavailable whenever GetAddressCardMaterial finds
      // nothing — which is exactly the case for every session in this file,
      // since all of them register through the legacy /v1/register path
      // (--dev-user), which creates an installation but never the
      // challenge/address-card material the guest flow creates. A double
      // that answered this unconditionally (as this fake used to) is more
      // permissive than production and hides exactly the bug this endpoint
      // exists to catch: it must fail here too, the same way, so the CLI's
      // fallback-to-server path is only ever exercised the way it really
      // will be.
      if (req.url === "/v1/whoami/card" && req.method === "GET") {
        res.statusCode = 404;
        return res.end(JSON.stringify({ error: "address_card_unavailable", message: "address card is unavailable" }));
      }
      if (req.url === "/v1/contexts" && req.method === "POST") {
        lastNameEnc = String(body.name_enc ?? "");
        ctxEpoch = 1;
        return res.end(JSON.stringify({ id: "c1", name_enc: body.name_enc, owner_uid: "1", epoch: ctxEpoch, version: 0, bytes: 0, updated_at: "", role: "owner" }));
      }
      if (req.url === "/v1/contexts" && req.method === "GET") {
        return res.end(JSON.stringify([{ id: "c1", name_enc: lastNameEnc, owner_uid: "1", epoch: ctxEpoch, version: ctxVersion, bytes: ctxHasContent ? 1 : 0, updated_at: "", role: ctxRole }]));
      }
      if (req.url === "/v1/contexts/pending" && req.method === "GET") {
        return res.end(JSON.stringify(pendingList));
      }
      if (req.url === "/v1/contexts/c1/members" && req.method === "GET") {
        return res.end(JSON.stringify(membersList));
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
          bytes: ctxHasContent ? 1 : 0, updated_at: "", role: ctxRole,
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
  it("answers a pending authorisation in passing when running an ordinary command, sourcing the box key from the server — not the local contact book", async () => {
    expect(await cli("register", "--dev-user", "9", "--allow-insecure-http")).toBe(0);
    await cli("context", "create", "--name", "n"); // we now hold c1's key locally
    const ourKey = new ContextKeys(home).get("c1")!;

    // Bob is on a genuinely DIFFERENT installation: derive his box key from a
    // distinct seed, exactly as a real second machine would. Deliberately
    // NOT added as a local contact — this is the propagation-gap scenario:
    // the server, not the address book, is what makes him reachable. The
    // server reports his installation id and current box key via
    // GET /v1/contexts/c1/members, exactly as the real endpoint would for a
    // genuine member.
    const bobSeed = Buffer.alloc(32, 0x42);
    const bobBoxKeys = installationBoxKeys(bobSeed);
    membersList = [
      { github_user_id: "42", role: "writer", added_at: "", installation_id: "install-bob", installation_box_key: bobBoxKeys.publicKey },
    ];
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
  });

  // The staleness defect this task closes: a local contact's cached box key
  // for a member can be behind the truth (the member's installation rotated
  // its key without every keyholder's cached copy catching up — this is
  // exactly how the fifth defect in this feature locked a recipient out
  // permanently). Piggyback answering must use the SERVER's current box key
  // for the member's installation, never the local contact's, even when a
  // local contact exists and even when it names the exact same installation
  // id.
  it("uses the server's current box key even when the local contact holds a stale one for the same installation", async () => {
    expect(await cli("register", "--dev-user", "9", "--allow-insecure-http")).toBe(0);
    await cli("context", "create", "--name", "n"); // we now hold c1's key locally
    const ourKey = new ContextKeys(home).get("c1")!;

    const staleSeed = Buffer.alloc(32, 0x11);
    const staleBoxKeys = installationBoxKeys(staleSeed);
    const currentSeed = Buffer.alloc(32, 0x22);
    const currentBoxKeys = installationBoxKeys(currentSeed);

    // Bob's local contact entry names the CORRECT installation id but an
    // OUTDATED box key for it.
    new Contacts(home).add("bob", {
      sessionId: "s-bob", publicKey: (await generateKeypair()).publicKey, githubUserId: "42",
      installationBoxKey: staleBoxKeys.publicKey, installationId: "install-bob",
    });
    // The server reports the CURRENT box key for that same installation id.
    membersList = [
      { github_user_id: "42", role: "writer", added_at: "", installation_id: "install-bob", installation_box_key: currentBoxKeys.publicKey },
    ];
    pendingList = [{ context_id: "c1", epoch: 1, github_user_id: "42", role: "writer", recipient_installation: "install-bob" }];

    const code = await cli("context", "list");
    expect(code).toBe(0);

    expect(uploadedEnvelopes).toHaveLength(1);
    expect(uploadedEnvelopes[0].envelopes).toHaveLength(1);
    const envelope = uploadedEnvelopes[0].envelopes[0];
    expect(envelope.recipient_installation).toBe("install-bob");
    // Openable with the server's CURRENT key...
    const opened = await open(envelope.sealed_key, currentBoxKeys.publicKey, currentBoxKeys.privateKey);
    expect(opened).toBe(ourKey);
    // ...and NOT with the stale one the local contact book held — proving
    // the stale local copy was never used to seal.
    await expect(open(envelope.sealed_key, staleBoxKeys.publicKey, staleBoxKeys.privateKey)).rejects.toThrow();
  });

  // A pending entry the server's member list has no current box key for
  // (e.g. installation info never reported) must stay pending — there is
  // nothing safe to seal with — rather than the command failing outright.
  it("leaves a pending entry unanswered when the server reports no box key for that installation", async () => {
    expect(await cli("register", "--dev-user", "9", "--allow-insecure-http")).toBe(0);
    await cli("context", "create", "--name", "n");

    membersList = [{ github_user_id: "42", role: "writer", added_at: "" }]; // no installation_id/box_key
    pendingList = [{ context_id: "c1", epoch: 1, github_user_id: "42", role: "writer", recipient_installation: "install-bob" }];

    const code = await cli("context", "list");
    expect(code).toBe(0);
    expect(uploadedEnvelopes).toHaveLength(0);
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
    // Deliberately give session id and installation id DIFFERENT values —
    // exactly the R4b/R7 bug: the CLI once addressed the envelope by
    // session id. If the fix regresses to that, the request-level
    // assertion below (recipient_installation) catches it even though
    // sealing itself would still "work" (both are just strings to seal()).
    new Contacts(home).add("alice", {
      sessionId: "s-alice", publicKey: aliceSessionKeys.publicKey, githubUserId: "7",
      installationBoxKey: aliceBoxKeys.publicKey, installationId: "install-alice",
    });

    const code = await cli("context", "share", "--id", "c1", "--to", "alice");
    expect(code).toBe(0);

    expect(addedMembers).toHaveLength(1);
    expect(addedMembers[0].github_user_id).toBe("7");
    // The critical assertion: what the SERVER actually received as
    // recipient_installation must be alice's installation id, and must NOT
    // be her session id. A test that only checked the sealed_key contents
    // (as before) could pass even with the session-id mis-addressing bug,
    // because seal() doesn't care what string it's given.
    expect(addedMembers[0].recipient_installation).toBe("install-alice");
    expect(addedMembers[0].recipient_installation).not.toBe("s-alice");
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
      installationBoxKey: "", installationId: "",
    });

    const errs: string[] = [];
    const spy = vi.spyOn(process.stderr, "write").mockImplementation((c: any) => (errs.push(String(c)), true));
    const code = await cli("context", "share", "--id", "c1", "--to", "alice");
    spy.mockRestore();

    expect(code).toBe(1);
    expect(errs.join("")).toMatch(/predates installation keys/i);
    expect(addedMembers).toHaveLength(0);
  });

  // Backward compatibility, the exact scenario this task exists to close: a
  // contact saved (or a card pasted) before installation identity existed
  // has an installationBoxKey (from the earlier R4b fix) but no
  // installationId. Sharing must refuse with a clear, actionable message —
  // never silently fall back to sessionId and send a mis-addressed
  // envelope the recipient can never recover from.
  it("share refuses with a clear message when the contact has a box key but no installation id", async () => {
    expect(await cli("register", "--dev-user", "9", "--allow-insecure-http")).toBe(0);
    await cli("context", "create", "--name", "n");
    const aliceBoxKeys = installationBoxKeys(Buffer.alloc(32, 0x99));
    new Contacts(home).add("alice", {
      sessionId: "s-alice", publicKey: (await generateKeypair()).publicKey, githubUserId: "7",
      installationBoxKey: aliceBoxKeys.publicKey, installationId: "",
    });

    const errs: string[] = [];
    const spy = vi.spyOn(process.stderr, "write").mockImplementation((c: any) => (errs.push(String(c)), true));
    const code = await cli("context", "share", "--id", "c1", "--to", "alice");
    spy.mockRestore();

    expect(code).toBe(1);
    expect(errs.join("")).toMatch(/predates installation identity/i);
    // No request must have gone out at all — a silent wrong-address is
    // exactly the failure this task exists to remove.
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

    // The propagation gap this task closes: rotation must reach a remaining
    // member who is NOT in the acting owner's local contacts. Before this
    // change, the owner's re-key pass (piggybacked through
    // answerPendingContextKeys) could only address members it found in its
    // own address book — a remaining member added by someone else, who never
    // exchanged cards with this owner, would get no envelope at all until
    // some unrelated third party who did have them as a contact happened to
    // run a command. Carol here is exactly that member: a genuine remaining
    // member of c1, deliberately never added to this owner's contacts.
    it("delivers the rotated key to a remaining member who is not in the owner's contacts (propagation gap)", async () => {
      expect(await cli("register", "--dev-user", "9", "--allow-insecure-http")).toBe(0);
      await cli("context", "create", "--name", "n"); // we hold c1's key locally

      const carolSeed = Buffer.alloc(32, 0x33);
      const carolBoxKeys = installationBoxKeys(carolSeed);
      // Carol is a current member per the server's own membership record...
      membersList = [
        { github_user_id: "1", role: "owner", added_at: "" },
        {
          github_user_id: "77", role: "writer", added_at: "",
          installation_id: "install-carol", installation_box_key: carolBoxKeys.publicKey,
        },
      ];
      // Deliberately NOT added to Contacts(home) — that is the whole point.

      const code = await cli("context", "revoke", "--id", "c1", "--user", "99");
      expect(code).toBe(0);
      const rotatedKey = new ContextKeys(home).get("c1")!;

      // Carol becomes pending for the new epoch once rotation has happened —
      // she has no envelope yet for it, exactly as the real server derives
      // it (see handleListPendingContextKeys). Any subsequent ordinary
      // command answers what it can, piggybacked.
      pendingList = [{ context_id: "c1", epoch: ctxEpoch, github_user_id: "77", role: "writer", recipient_installation: "install-carol" }];
      const code2 = await cli("context", "list");
      expect(code2).toBe(0);

      const carolEnvelope = uploadedEnvelopes
        .flatMap((u) => u.envelopes)
        .find((e) => e.recipient_installation === "install-carol");
      expect(carolEnvelope).toBeDefined();
      // Genuinely usable on Carol's machine: her installation box private
      // key, derived independently from her own seed, opens it, and it is
      // the real (rotated) context key — not the pre-revoke one.
      const opened = await open(carolEnvelope!.sealed_key, carolBoxKeys.publicKey, carolBoxKeys.privateKey);
      expect(opened).toBe(rotatedKey);
    });
  });

  // R5 — the recovery code: generated client-side from the key `create`
  // already holds, shown once, and never uploaded anywhere. See
  // docs/shared-context-keys.html §"恢复码：借用 AK/SK 的模式，但只借一半".
  describe("recovery code", () => {
    it("prints the recovery code exactly once, in a distinct block, on create", async () => {
      expect(await cli("register", "--dev-user", "9", "--allow-insecure-http")).toBe(0);
      const errs: string[] = [];
      const espy = vi.spyOn(process.stderr, "write").mockImplementation((c: any) => (errs.push(String(c)), true));
      const code = await cli("context", "create", "--name", "team notes");
      espy.mockRestore();

      expect(code).toBe(0);
      const msg = errs.join("");
      // A visually distinct block with the required warning.
      expect(msg).toMatch(/recovery code/i);
      expect(msg).toMatch(/restore.*(entire|whole|all).*context|context.*(entire|whole|all).*restore/i);
      expect(msg).toMatch(/not.*(store|save|paste).*online|offline/i);
      const match = msg.match(/AMSC1-[0-9A-Z-]+/);
      expect(match).toBeTruthy();
      // Shown exactly once: the block header appears once per create call.
      expect((msg.match(/RECOVERY CODE/gi) || []).length).toBe(1);
    });

    it("never sends the recovery code to the server — checked against captured request bodies", async () => {
      expect(await cli("register", "--dev-user", "9", "--allow-insecure-http")).toBe(0);
      const errs: string[] = [];
      const espy = vi.spyOn(process.stderr, "write").mockImplementation((c: any) => (errs.push(String(c)), true));
      const code = await cli("context", "create", "--name", "team notes");
      espy.mockRestore();
      expect(code).toBe(0);

      const printedCode = errs.join("").match(/AMSC1-[0-9A-Z-]+/)?.[0];
      expect(printedCode).toBeTruthy();
      // Also check the raw base64 key itself, not just its recovery-code
      // encoding — belt and suspenders on the property the whole design
      // rests on.
      const rawKey = new ContextKeys(home).get("c1")!;
      for (const body of allRequestBodies) {
        expect(body).not.toContain(printedCode);
        expect(body).not.toContain(rawKey);
      }
    });

    it("a second create for a different context prints a different code", async () => {
      expect(await cli("register", "--dev-user", "9", "--allow-insecure-http")).toBe(0);
      const errs1: string[] = [];
      let espy = vi.spyOn(process.stderr, "write").mockImplementation((c: any) => (errs1.push(String(c)), true));
      await cli("context", "create", "--name", "first");
      espy.mockRestore();

      const errs2: string[] = [];
      espy = vi.spyOn(process.stderr, "write").mockImplementation((c: any) => (errs2.push(String(c)), true));
      await cli("context", "create", "--name", "second");
      espy.mockRestore();

      const code1 = errs1.join("").match(/AMSC1-[0-9A-Z-]+/)?.[0];
      const code2 = errs2.join("").match(/AMSC1-[0-9A-Z-]+/)?.[0];
      expect(code1).toBeTruthy();
      expect(code2).toBeTruthy();
      expect(code1).not.toBe(code2);
    });

    it("export-recovery re-derives the same code the owner would have seen at creation", async () => {
      expect(await cli("register", "--dev-user", "9", "--allow-insecure-http")).toBe(0);
      const createErrs: string[] = [];
      let espy = vi.spyOn(process.stderr, "write").mockImplementation((c: any) => (createErrs.push(String(c)), true));
      await cli("context", "create", "--name", "n");
      espy.mockRestore();
      const createdCode = createErrs.join("").match(/AMSC1-[0-9A-Z-]+/)?.[0];

      const exportErrs: string[] = [];
      espy = vi.spyOn(process.stderr, "write").mockImplementation((c: any) => (exportErrs.push(String(c)), true));
      const code = await cli("context", "export-recovery", "--id", "c1");
      espy.mockRestore();

      expect(code).toBe(0);
      const exportedCode = exportErrs.join("").match(/AMSC1-[0-9A-Z-]+/)?.[0];
      expect(exportedCode).toBe(createdCode);
    });

    it("export-recovery is refused for a non-owner, with no code printed", async () => {
      expect(await cli("register", "--dev-user", "9", "--allow-insecure-http")).toBe(0);
      await cli("context", "create", "--name", "n"); // we hold the key locally
      ctxRole = "writer"; // ...but the server now says we're not the owner

      const errs: string[] = [];
      const espy = vi.spyOn(process.stderr, "write").mockImplementation((c: any) => (errs.push(String(c)), true));
      const code = await cli("context", "export-recovery", "--id", "c1");
      espy.mockRestore();

      expect(code).toBe(1);
      const msg = errs.join("");
      expect(msg).toMatch(/owner/i);
      expect(msg).not.toMatch(/AMSC1-/);
    });

    it("import-recovery restores the key into a fresh local store that lost all state", async () => {
      expect(await cli("register", "--dev-user", "9", "--allow-insecure-http")).toBe(0);
      const createErrs: string[] = [];
      const espy = vi.spyOn(process.stderr, "write").mockImplementation((c: any) => (createErrs.push(String(c)), true));
      await cli("context", "create", "--name", "n");
      espy.mockRestore();
      const originalKey = new ContextKeys(home).get("c1")!;
      const recoveryCode = createErrs.join("").match(/AMSC1-[0-9A-Z-]+/)?.[0]!;
      expect(recoveryCode).toBeTruthy();

      // Simulate every keyholder having lost local state: a brand new home
      // with no contexts.json at all, registering fresh.
      const home2 = mkdtempSync(join(tmpdir(), "amsg-ctx-fresh-"));
      try {
        process.env.AGENTMSG_HOME = home2;
        process.env.AGENTMSG_SERVER = base;
        delete process.env.AGENTMSG_PROFILE;
        expect(await run(["register", "--dev-user", "9", "--allow-insecure-http"])).toBe(0);
        expect(new ContextKeys(home2).get("c1")).toBeUndefined(); // precondition: no local key at all

        const code = await run(["context", "import-recovery", "--id", "c1", "--code", recoveryCode]);
        expect(code).toBe(0);
        expect(new ContextKeys(home2).get("c1")).toBe(originalKey);
      } finally {
        delete process.env.AGENTMSG_HOME;
        delete process.env.AGENTMSG_SERVER;
        rmSync(home2, { recursive: true, force: true });
      }
    });

    it("import-recovery gives a clear error (not a crash) for a garbled code", async () => {
      expect(await cli("register", "--dev-user", "9", "--allow-insecure-http")).toBe(0);
      const errs: string[] = [];
      const espy = vi.spyOn(process.stderr, "write").mockImplementation((c: any) => (errs.push(String(c)), true));
      const code = await cli("context", "import-recovery", "--id", "c1", "--code", "not-a-real-code");
      espy.mockRestore();

      expect(code).toBe(1);
      expect(errs.join("")).toMatch(/invalid|checksum|malformed/i);
      expect(new ContextKeys(home).get("c1")).toBeUndefined();
    });
  });
});

// R8 end-to-end: two genuinely distinct identities register, exchange real
// address cards, and share a context — with nothing on the identity path
// fabricated by the test. This is the regression test for the bug this task
// exists to fix: POST /v1/register's response omitted installation_id, so
// `session.installationId` was never populated for the verified/--dev-user
// path, `compactCard()` emitted a card with no installation id, and `contact
// add --card` stored `installationId: ""` — which made `context share`
// refuse for a brand-new installation with "this contact's card predates
// installation identity". Every other sharing test in this file fabricates
// the recipient's installation id/box key by hand (installationBoxKeys(seed)
// + Contacts.add() directly), which is exactly why none of them caught this:
// the bug lives entirely in the register -> card -> contact-add plumbing
// that those tests skip. This test drives that plumbing for real, for BOTH
// parties, using two separate home directories so their installation seeds
// are independently random — the same as two real machines — and would have
// failed (share refusing with "predates installation identity") before the
// fix in src/cli.ts's cmdRegister.
describe("end-to-end sharing between two real registrations (no fabricated identity)", () => {
  it("self shares a context with peer via register -> card -> contact add -> share, and peer decrypts it", async () => {
    // A dedicated fake server for this test: unlike the shared one above, it
    // must route sealed_key by the CALLING installation (via bearer token),
    // the way the real server's handleGetContext does with
    // sess.InstallationID — because self and peer are two different callers
    // who must see two different envelopes for the same context.
    const regs = new Map<string, { installationId: string; githubUserId: string; sessionId: string }>();
    let regCounter = 0;
    const ctx = { nameEnc: "", version: 0, epoch: 1, content: "", hasContent: false };
    const sealedKeys = new Map<string, string>(); // installationId -> sealed_key
    let e2eServer: Server;
    let e2eBase = "";

    await new Promise<void>((resolve) => {
      e2eServer = createServer((req, res) => {
        let b = "";
        req.on("data", (c) => (b += c));
        req.on("end", () => {
          let body: any = {};
          try {
            body = b ? JSON.parse(b) : {};
          } catch {
            body = {};
          }
          res.setHeader("Content-Type", "application/json");
          const authHeader = req.headers["authorization"];
          const token = typeof authHeader === "string" && authHeader.startsWith("Bearer ") ? authHeader.slice(7) : "";
          const caller = regs.get(token);

          if (req.url === "/v1/register" && req.method === "POST") {
            regCounter++;
            const reg = {
              installationId: `ins_e2e${regCounter}`,
              githubUserId: `${9000 + regCounter}`,
              sessionId: `ses_e2e${regCounter}`,
            };
            const newToken = `tok_e2e${regCounter}`;
            regs.set(newToken, reg);
            return res.end(JSON.stringify({
              session_id: reg.sessionId, token: newToken, github_login: `user${regCounter}`,
              github_user_id: reg.githubUserId, installation_id: reg.installationId,
            }));
          }
          // Presigned upload/download URLs carry no bearer token (the URL
          // itself is the capability — see Client.uploadPut/download), so
          // these must be handled before the auth gate below.
          if (req.url === "/upload") {
            ctx.content = b;
            ctx.hasContent = true;
            return res.end("{}");
          }
          if (req.url === "/download-content" && req.method === "GET") {
            return res.end(ctx.content);
          }
          if (!caller) {
            res.statusCode = 401;
            return res.end(JSON.stringify({ error: "unauthenticated", message: "unauthenticated" }));
          }
          // Mirrors production: the legacy register path never creates
          // address-card material, so this always 404s for these sessions.
          if (req.url === "/v1/whoami/card" && req.method === "GET") {
            res.statusCode = 404;
            return res.end(JSON.stringify({ error: "address_card_unavailable" }));
          }
          if (req.url === "/v1/contexts/pending" && req.method === "GET") {
            return res.end(JSON.stringify([]));
          }
          if (req.url === "/v1/contexts" && req.method === "POST") {
            ctx.nameEnc = String(body.name_enc ?? "");
            ctx.epoch = 1;
            ctx.version = 0;
            return res.end(JSON.stringify({
              id: "c1", name_enc: ctx.nameEnc, owner_uid: caller.githubUserId,
              epoch: ctx.epoch, version: ctx.version, bytes: 0, updated_at: "", role: "owner",
            }));
          }
          if (req.url === "/v1/contexts/c1" && req.method === "GET") {
            return res.end(JSON.stringify({
              id: "c1", name_enc: ctx.nameEnc, owner_uid: "", epoch: ctx.epoch, version: ctx.version,
              bytes: ctx.hasContent ? 1 : 0, updated_at: "", role: "writer",
              download_url: ctx.hasContent ? e2eBase + "/download-content" : undefined,
              sealed_key: sealedKeys.get(caller.installationId),
            }));
          }
          if (req.url === "/v1/contexts/c1" && req.method === "PUT") {
            return res.end(JSON.stringify({ upload_url: e2eBase + "/upload", blob_key: "k" }));
          }
          if (req.url === "/v1/contexts/c1/commit" && req.method === "POST") {
            if (body.expected_version !== ctx.version) {
              res.statusCode = 409;
              return res.end(JSON.stringify({ error: "version_conflict", current_version: ctx.version }));
            }
            ctx.version++;
            return res.end(JSON.stringify({
              id: "c1", name_enc: ctx.nameEnc, owner_uid: "", epoch: ctx.epoch, version: ctx.version,
              bytes: ctx.content.length, updated_at: "", role: "owner",
            }));
          }
          if (req.url === "/v1/contexts/c1/members" && req.method === "POST") {
            if (body.sealed_key && body.recipient_installation) {
              sealedKeys.set(String(body.recipient_installation), String(body.sealed_key));
            }
            return res.end(JSON.stringify({ status: "added" }));
          }
          res.end("{}");
        });
      });
      e2eServer.listen(0, () => resolve());
    });
    const addr = e2eServer!.address();
    e2eBase = `http://127.0.0.1:${typeof addr === "object" && addr ? addr.port : 0}`;

    const selfHome = mkdtempSync(join(tmpdir(), "amsg-e2e-self-"));
    const peerHome = mkdtempSync(join(tmpdir(), "amsg-e2e-peer-"));
    async function cliAs(h: string, ...argv: string[]) {
      process.env.AGENTMSG_HOME = h;
      process.env.AGENTMSG_SERVER = e2eBase;
      delete process.env.AGENTMSG_PROFILE;
      const code = await run(argv);
      delete process.env.AGENTMSG_HOME;
      delete process.env.AGENTMSG_SERVER;
      return code;
    }
    async function cliCapture(h: string, ...argv: string[]): Promise<{ code: number; out: string }> {
      const out: string[] = [];
      const spy = vi.spyOn(process.stdout, "write").mockImplementation((c: any) => (out.push(String(c)), true));
      let code: number;
      try {
        code = await cliAs(h, ...argv);
      } finally {
        spy.mockRestore();
      }
      return { code, out: out.join("") };
    }

    try {
      expect(await cliAs(selfHome, "register", "--dev-user", "1", "--allow-insecure-http")).toBe(0);
      expect(await cliAs(peerHome, "register", "--dev-user", "2", "--allow-insecure-http")).toBe(0);

      // Peer produces their OWN card exactly as a user would (`agentmsg
      // card`) — not a hand-built Contacts.add() call. This is the exact
      // path that used to emit `iid: undefined` because
      // session.installationId was never populated.
      const peerCardOut = await cliCapture(peerHome, "card");
      expect(peerCardOut.code).toBe(0);
      const peerCard = JSON.parse(peerCardOut.out) as { card: string; installation_id?: string };
      expect(peerCard.installation_id).toBeTruthy(); // the exact field this task adds
      expect(peerCard.card.startsWith("am1:")).toBe(true);
      const peerCardPayload = JSON.parse(Buffer.from(peerCard.card.slice(4), "base64url").toString("utf8"));
      expect(peerCardPayload.iid).toBeTruthy(); // must be embedded in the wire card, not just the local field

      // Self imports the peer's card via the real `contact add --card` path.
      expect(await cliAs(selfHome, "contact", "add", "peer", "--card", peerCard.card)).toBe(0);

      const createOut = await cliCapture(selfHome, "context", "create", "--name", "shared doc");
      expect(createOut.code).toBe(0);
      const created = JSON.parse(createOut.out) as { context_id: string };
      expect(created.context_id).toBe("c1");

      expect(await cliAs(selfHome, "context", "set", "--id", "c1", "--text", "hello peer", "--expect", "0")).toBe(0);

      // The guard this task must NOT weaken: this call must actually reach
      // the server (not refuse with "predates installation identity") now
      // that the peer's card genuinely carries an installation id.
      expect(await cliAs(selfHome, "context", "share", "--id", "c1", "--to", "peer")).toBe(0);

      const getOut = await cliCapture(peerHome, "context", "get", "--id", "c1");
      expect(getOut.code).toBe(0);
      expect(JSON.parse(getOut.out)).toMatchObject({ context_id: "c1", text: "hello peer" });
    } finally {
      rmSync(selfHome, { recursive: true, force: true });
      rmSync(peerHome, { recursive: true, force: true });
      await new Promise<void>((r) => e2eServer.close(() => r()));
    }
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
