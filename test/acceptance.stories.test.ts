// Acceptance suite: user stories run end to end against a REAL Go server
// binary via the REAL CLI (src/cli.ts's exported `run()`), exactly the way a
// human or an agent would invoke it. No fake server, no fabricated identity,
// no hand-made key.
//
// Why this file exists: six defects in the shared-context feature reached
// "reviewed and green" because in-process test doubles (see context.test.ts's
// fixture HTTP server) were more permissive than the real server — most
// notably, the fake /commit handler never checked blob_key, so 174 green
// tests coexisted with a feature that could not write at all (see
// client.ts's commitContext / cli.ts's `context set`). This file is the
// last line of defence those doubles cannot be: every story below drives the
// built CLI against a real `agentmsg-server` process, with real identities
// registered over the wire and real HTTP round-trips for every assertion.
//
// Gating follows the existing convention in go-server.integration.test.ts:
// AGENTMSG_GO_SERVER must point at a running server (dev auth, in-memory
// store, fake blob — see the CI workflow's `cli_integration` job, or run
// scripts/run-acceptance-server.sh locally, or start it by hand):
//
//   GOTOOLCHAIN=local CGO_ENABLED=0 go build -o /tmp/agentmsg-server ./cmd/server   (in sc-server)
//   PORT=18080 AUTH_MODE=dev STORE_MODE=mem BLOB_MODE=fake MODERATION_MODE=rules \
//   GUEST_REGISTRATION_MODE=rules GUEST_SERVER_ORIGIN=http://127.0.0.1:18080 \
//   GUEST_TOKEN_KEY=0123456789abcdef0123456789abcdef \
//   GUEST_LOW_RISK_CIDRS=127.0.0.1/32 GUEST_MEDIUM_RISK_CIDRS=198.51.100.0/24 \
//   GUEST_POW_DIFFICULTY_BITS=4 /tmp/agentmsg-server > /tmp/agentmsg-server.log 2>&1 &
//
//   AGENTMSG_GO_SERVER=http://127.0.0.1:18080 npx vitest run test/acceptance.stories.test.ts
//
// Without AGENTMSG_GO_SERVER set, every story below is SKIPPED (not faked) —
// see `suite` below.
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { run } from "../src/cli.js";

const serverURL = process.env.AGENTMSG_GO_SERVER;
const suite = serverURL ? describe : describe.skip;
if (!serverURL) {
  // eslint-disable-next-line no-console
  console.warn(
    "acceptance.stories.test.ts: AGENTMSG_GO_SERVER not set — skipping the real-server acceptance suite. " +
      "See the file header for how to start a server and run it.",
  );
}

// A fresh, ever-increasing dev-user id per identity so stories never collide
// on server-side per-account state (context ownership quota, feedback quota,
// default policy) even though the store is in-memory and shared across the
// whole file (fileParallelism is off — see vitest.config.ts — so this is
// safe without a lock).
let nextUid = 700_000;
function freshUid(): number {
  return nextUid++;
}

function freshHome(tag: string): string {
  return mkdtempSync(join(tmpdir(), `amsg-accept-${tag}-`));
}

/** Runs one CLI invocation as the identity rooted at `h`, discarding output. */
async function cliAs(h: string, ...argv: string[]): Promise<number> {
  process.env.AGENTMSG_HOME = h;
  process.env.AGENTMSG_SERVER = serverURL;
  delete process.env.AGENTMSG_PROFILE;
  try {
    return await run(argv);
  } finally {
    delete process.env.AGENTMSG_HOME;
    delete process.env.AGENTMSG_SERVER;
  }
}

/** Same as cliAs, but also pins AGENTMSG_PROFILE — for simulating a second
 *  agent session sharing one machine identity (story 5). */
async function cliAsProfile(h: string, profile: string, ...argv: string[]): Promise<number> {
  process.env.AGENTMSG_HOME = h;
  process.env.AGENTMSG_SERVER = serverURL;
  process.env.AGENTMSG_PROFILE = profile;
  try {
    return await run(argv);
  } finally {
    delete process.env.AGENTMSG_HOME;
    delete process.env.AGENTMSG_SERVER;
    delete process.env.AGENTMSG_PROFILE;
  }
}

interface Captured {
  code: number;
  out: string; // stdout (the JSON the CLI emits on success)
  err: string; // stderr (human notes, and the top-level "error: ..." line)
}

/** Runs one CLI invocation, capturing both stdout (JSON) and stderr (notes/errors). */
async function cliCapture(h: string, ...argv: string[]): Promise<Captured> {
  const out: string[] = [];
  const err: string[] = [];
  const outSpy = vi.spyOn(process.stdout, "write").mockImplementation((c: any) => (out.push(String(c)), true));
  const errSpy = vi.spyOn(process.stderr, "write").mockImplementation((c: any) => (err.push(String(c)), true));
  let code: number;
  try {
    code = await cliAs(h, ...argv);
  } finally {
    outSpy.mockRestore();
    errSpy.mockRestore();
  }
  return { code, out: out.join(""), err: err.join("") };
}

async function cliCaptureProfile(h: string, profile: string, ...argv: string[]): Promise<Captured> {
  const out: string[] = [];
  const err: string[] = [];
  const outSpy = vi.spyOn(process.stdout, "write").mockImplementation((c: any) => (out.push(String(c)), true));
  const errSpy = vi.spyOn(process.stderr, "write").mockImplementation((c: any) => (err.push(String(c)), true));
  let code: number;
  try {
    code = await cliAsProfile(h, profile, ...argv);
  } finally {
    outSpy.mockRestore();
    errSpy.mockRestore();
  }
  return { code, out: out.join(""), err: err.join("") };
}

function json<T = any>(c: Captured): T {
  return JSON.parse(c.out) as T;
}

/** Registers a fresh dev identity in `h` and returns its session JSON
 *  (session_id, github_user_id, installation_id, ...) — the real
 *  `agentmsg register --dev-user` path, talking to the real server.
 *
 *  The server's per-IP registration limiter (registerRatePerSec=1,
 *  registerBurst=15 — api.go) is shared by every identity this whole suite
 *  registers, all from 127.0.0.1. That is a real, correct production
 *  behaviour (it stops registration abuse), not a test bug — so rather than
 *  disabling or working around it, this retries with backoff on the same
 *  "rate_limited" response a real client would see, exactly as a real CLI
 *  user would (the top-level error even names a Retry-After). */
async function registerDev(h: string, uid: number, attempt = 0): Promise<any> {
  const c = await cliCapture(h, "register", "--dev-user", String(uid), "--allow-insecure-http");
  if (c.code !== 0 && /rate_limited/.test(c.err) && attempt < 10) {
    await new Promise((r) => setTimeout(r, 1100));
    return registerDev(h, uid, attempt + 1);
  }
  expect(c.code, `register --dev-user ${uid} failed: ${c.err}`).toBe(0);
  return json(c);
}

async function getCard(h: string): Promise<any> {
  const c = await cliCapture(h, "card");
  expect(c.code, `card failed: ${c.err}`).toBe(0);
  return json(c);
}

/** Removes a saved contact directly from the on-disk address book, without
 *  going through the CLI — used to simulate "never exchanged cards with this
 *  member" after a share that required momentarily knowing their card. */
function forgetContact(home: string, name: string): void {
  const file = join(home, "contacts.json");
  const all = JSON.parse(readFileSync(file, "utf8")) as Record<string, unknown>;
  delete all[name];
  writeFileSync(file, JSON.stringify(all, null, 2), { mode: 0o600 });
}

function tailServerLog(lines = 80): string {
  const path = process.env.AGENTMSG_GO_SERVER_LOG || "/tmp/agentmsg-server.log";
  try {
    return readFileSync(path, "utf8").split("\n").slice(-lines).join("\n");
  } catch {
    return `(no server log found at ${path}; set AGENTMSG_GO_SERVER_LOG to point at it)`;
  }
}

/** Wraps a story so a failure prints which story broke and the tail of the
 *  real server's log, without anyone having to re-derive that locally from a
 *  bare vitest stack trace. */
function story(name: string, fn: () => Promise<void>, timeout?: number): void {
  it(name, async () => {
    try {
      await fn();
    } catch (e) {
      // eslint-disable-next-line no-console
      console.error(
        `\n>>> STORY FAILED: ${name}\n>>> server log tail (${process.env.AGENTMSG_GO_SERVER_LOG || "/tmp/agentmsg-server.log"}):\n${tailServerLog()}\n>>> end server log tail\n`,
      );
      throw e;
    }
  }, timeout);
}

suite("shared-context & product acceptance stories (real server, real CLI)", () => {
  const homes: string[] = [];
  function home(tag: string): string {
    const h = freshHome(tag);
    homes.push(h);
    return h;
  }
  afterEach(() => {
    for (const h of homes.splice(0)) rmSync(h, { recursive: true, force: true });
  });

  story("1. create a context, write content, read it back — plaintext survives the round trip", async () => {
    const a = home("s1-a");
    await registerDev(a, freshUid());

    const created = json(await cliCapture(a, "context", "create", "--name", "story1"));
    expect(created.context_id).toBeTruthy();
    const id = created.context_id as string;

    const setRes = await cliCapture(a, "context", "set", "--id", id, "--text", "hello, shared context", "--expect", "0");
    expect(setRes.code, `context set failed: ${setRes.err}`).toBe(0);
    expect(json(setRes).version).toBe(1);

    const got = json(await cliCapture(a, "context", "get", "--id", id));
    expect(got).toMatchObject({ context_id: id, version: 1, text: "hello, shared context" });
  });

  story("2. two people: A shares with B via a real card exchange; B reads", async () => {
    const a = home("s2-a");
    const b = home("s2-b");
    await registerDev(a, freshUid());
    await registerDev(b, freshUid());

    const created = json(await cliCapture(a, "context", "create", "--name", "story2"));
    const id = created.context_id as string;
    expect((await cliCapture(a, "context", "set", "--id", id, "--text", "shared with b", "--expect", "0")).code).toBe(0);

    // Real card exchange: B produces their own card with `agentmsg card`,
    // A imports it with `agentmsg contact add --card` — not a hand-built
    // Contacts.add() call.
    const bCard = await getCard(b);
    expect(bCard.card.startsWith("am1:")).toBe(true);
    expect(await cliAs(a, "contact", "add", "bob", "--card", bCard.card)).toBe(0);

    expect((await cliCapture(a, "context", "share", "--id", id, "--to", "bob")).code).toBe(0);

    const got = json(await cliCapture(b, "context", "get", "--id", id));
    expect(got).toMatchObject({ context_id: id, text: "shared with b" });
  });

  story(
    "3. conflict: two writers from the same version; the loser gets 409 with the current version, and can fetch, merge, retry successfully",
    async () => {
      const a = home("s3-a");
      const b = home("s3-b");
      await registerDev(a, freshUid());
      await registerDev(b, freshUid());

      const created = json(await cliCapture(a, "context", "create", "--name", "story3"));
      const id = created.context_id as string;
      expect((await cliCapture(a, "context", "set", "--id", id, "--text", "base", "--expect", "0")).code).toBe(0);

      const bCard = await getCard(b);
      expect(await cliAs(a, "contact", "add", "bob", "--card", bCard.card)).toBe(0);
      expect((await cliCapture(a, "context", "share", "--id", id, "--to", "bob")).code).toBe(0);

      // B imports the current key/content by reading once.
      expect(json(await cliCapture(b, "context", "get", "--id", id)).text).toBe("base");

      // A writes first, from version 1 -> 2.
      const aWrite = await cliCapture(a, "context", "set", "--id", id, "--text", "from A", "--expect", "1");
      expect(aWrite.code, `A's write should have won: ${aWrite.err}`).toBe(0);
      expect(json(aWrite).version).toBe(2);

      // B writes from the SAME base version (1) that A started from — B is
      // the loser here, deterministically (not a race): the server is
      // already at version 2.
      const bWrite = await cliCapture(b, "context", "set", "--id", id, "--text", "from B", "--expect", "1");
      expect(bWrite.code).toBe(1);
      expect(bWrite.err).toContain("version_conflict");
      expect(bWrite.err).toContain("version 2");

      // B fetches the version it missed, merges, and retries with the
      // current version as --expect. This must actually succeed against the
      // real server (this is exactly the path that could never run while
      // commitContext never sent blob_key).
      const current = json(await cliCapture(b, "context", "get", "--id", id));
      expect(current.version).toBe(2);
      expect(current.text).toBe("from A");
      const merged = `${current.text} + from B (merged)`;
      const retry = await cliCapture(b, "context", "set", "--id", id, "--text", merged, "--expect", String(current.version));
      expect(retry.code, `merge/retry failed: ${retry.err}`).toBe(0);
      expect(json(retry).version).toBe(3);

      const final = json(await cliCapture(a, "context", "get", "--id", id));
      expect(final.text).toBe(merged);
    },
  );

  // Regression coverage for task R12: `context revoke`'s self-key-delivery
  // step (uploadContextKeys(id, [{recipient_installation: selfInstallationId,
  // ...}])) used to get 403 recipient_not_member from the server, because
  // ContextMember.RecipientInstallation was never populated for the owner's
  // own row (see api_context.go's handleCreateContext). handleRotateKeys'
  // validRecipient set could then never contain the owner's own installation,
  // that throw aborted cmdContext's revoke handler BEFORE it reached
  // answerPendingContextKeys, and it did not self-heal on a later command
  // either — handleListPendingContextKeys requires the answering caller to
  // already hold a SERVER-STORED envelope for their own installation at the
  // current epoch, which the owner could never obtain. Net effect: after any
  // revoke with 2+ remaining members, the remaining non-acting members were
  // permanently locked out of the rotated content, with no user-visible
  // error. Fixed by having handleCreateContext populate the owner's
  // RecipientInstallation from the creating session's installation id, and
  // by rejecting an empty RecipientInstallation at the store boundary (see
  // Mem/pg.Store CreateContext / AddContextMember) so this can't regress
  // silently again.
  story(
    "4. removal: A removes B and rotates; B cannot read new content; every remaining member still can, including one not in A's contact book",
    async () => {
      const a = home("s4-a");
      const b = home("s4-b");
      const c = home("s4-c");
      await registerDev(a, freshUid());
      await registerDev(b, freshUid());
      await registerDev(c, freshUid());

      const created = json(await cliCapture(a, "context", "create", "--name", "story4"));
      const id = created.context_id as string;
      expect((await cliCapture(a, "context", "set", "--id", id, "--text", "v1", "--expect", "0")).code).toBe(0);

      const bCard = await getCard(b);
      const cCard = await getCard(c);
      expect(await cliAs(a, "contact", "add", "bob", "--card", bCard.card)).toBe(0);
      expect(await cliAs(a, "contact", "add", "carol", "--card", cCard.card)).toBe(0);
      expect((await cliCapture(a, "context", "share", "--id", id, "--to", "bob")).code).toBe(0);
      expect((await cliCapture(a, "context", "share", "--id", id, "--to", "carol")).code).toBe(0);

      // A never actually keeps Carol as a contact after inviting her — this
      // is what "a member not in A's contact book" means: A's OWN address
      // book has no entry for her by the time the rotation below runs, so
      // if delivery to her depended on A's local contacts (the bug this
      // story exists to catch), it would silently fail.
      forgetContact(a, "carol");

      // Both B and C read the original content and import the epoch-1 key.
      expect(json(await cliCapture(b, "context", "get", "--id", id)).text).toBe("v1");
      expect(json(await cliCapture(c, "context", "get", "--id", id)).text).toBe("v1");

      const bWhoami = json(await cliCapture(b, "whoami"));
      const revoke = await cliCapture(a, "context", "revoke", "--id", id, "--user", String(bWhoami.github_user_id));
      expect(revoke.code, `revoke failed: ${revoke.err}`).toBe(0);
      expect(json(revoke).rotated).toBe(true);

      // B: removed. Cannot read new content (or anything else on this
      // context — membership itself is gone).
      const bAfter = await cliCapture(b, "context", "get", "--id", id);
      expect(bAfter.code).toBe(1);
      expect(bAfter.err).toContain("not_a_member");

      // C: still a member, was never in A's local contact book, and
      // received the rotated key purely via the server-sourced piggyback
      // path (see answerPendingContextKeys in cli.ts) — no action of her
      // own was needed before this read.
      const cAfter = json(await cliCapture(c, "context", "get", "--id", id));
      expect(cAfter.text).toBe("v1");
      expect(cAfter.version).toBe(2); // rotate re-encrypts and re-commits existing content under the new epoch

      // A, the owner, can of course still read too.
      expect(json(await cliCapture(a, "context", "get", "--id", id)).text).toBe("v1");
    },
  );

  story(
    "5. same person, second agent session on one machine: session state isolated, context still readable",
    async () => {
      const machine = home("s5-machine");
      const uid = freshUid();

      const s1 = await registerDev(machine, uid); // implicitly profile-less == base home
      // Second session, same person, same machine (same AGENTMSG_HOME), but
      // its own profile subdirectory — the pattern a second concurrent agent
      // session (or a fresh terminal) produces.
      const s2Cap = await cliCaptureProfile(machine, "session-two", "register", "--dev-user", String(uid), "--allow-insecure-http");
      expect(s2Cap.code, `second session register failed: ${s2Cap.err}`).toBe(0);
      const s2 = json(s2Cap);

      // Session state (the token/session id each holds) is genuinely
      // distinct — these are two different logins, not a shared file.
      expect(s2.session_id).not.toBe(s1.session_id);
      // ... but they're provably the same person server-side.
      expect(s2.github_user_id).toBe(s1.github_user_id);

      const created = json(await cliCaptureProfile(machine, "session-two", "context", "create", "--name", "story5"));
      const id = created.context_id as string;
      expect(
        (await cliCaptureProfile(machine, "session-two", "context", "set", "--id", id, "--text", "from session two", "--expect", "0")).code,
      ).toBe(0);

      // The FIRST session (base profile, never ran `context share` with
      // anyone) can still read it straight away: the shared-context key
      // lives at the machine's base home regardless of which profile wrote
      // it, because it's the same installation identity underneath.
      const gotFromFirst = json(await cliCapture(machine, "context", "get", "--id", id));
      expect(gotFromFirst.text).toBe("from session two");
    },
  );

  // Regression coverage for task R12: same root cause as story 4 (see the
  // comment above it) — before the fix, the revoke that should trigger B's
  // automatic recovery never completed its piggyback delivery.
  story("6. a stale local key after a rotation recovers automatically", async () => {
    const a = home("s6-a");
    const b = home("s6-b");
    const c = home("s6-c");
    await registerDev(a, freshUid());
    await registerDev(b, freshUid());
    await registerDev(c, freshUid());

    const created = json(await cliCapture(a, "context", "create", "--name", "story6"));
    const id = created.context_id as string;
    expect((await cliCapture(a, "context", "set", "--id", id, "--text", "epoch1", "--expect", "0")).code).toBe(0);

    const bCard = await getCard(b);
    const cCard = await getCard(c);
    expect(await cliAs(a, "contact", "add", "bob", "--card", bCard.card)).toBe(0);
    expect(await cliAs(a, "contact", "add", "carol", "--card", cCard.card)).toBe(0);
    expect((await cliCapture(a, "context", "share", "--id", id, "--to", "bob")).code).toBe(0);
    expect((await cliCapture(a, "context", "share", "--id", id, "--to", "carol")).code).toBe(0);

    // B imports the epoch-1 key now — this is the key that will go stale.
    expect(json(await cliCapture(b, "context", "get", "--id", id)).text).toBe("epoch1");

    // A revokes Carol (NOT B). This bumps the epoch and rotates the content
    // key. B is still a legitimate member throughout, but B's on-disk key is
    // now for a dead epoch. Nothing here is done from B's side.
    const cWhoami = json(await cliCapture(c, "whoami"));
    const revoke = await cliCapture(a, "context", "revoke", "--id", id, "--user", String(cWhoami.github_user_id));
    expect(revoke.code, `revoke failed: ${revoke.err}`).toBe(0);

    // B's very next ordinary command — a plain `context get`, nothing
    // special — must transparently notice the stale epoch, pull the fresh
    // envelope the server already has waiting (delivered by A's revoke via
    // piggyback answering), and decrypt correctly. No manual re-share step.
    const bAfterCap = await cliCapture(b, "context", "get", "--id", id);
    expect(bAfterCap.code, `B could not read after rotation: ${bAfterCap.err}`).toBe(0);
    const bAfter = json(bAfterCap);
    expect(bAfter.text).toBe("epoch1");
    expect(bAfter.epoch).toBeGreaterThan(1);
  });

  story("7. recovery code: shown once, restores access after total local state loss", async () => {
    const a = home("s7-a");
    const uid = freshUid();
    await registerDev(a, uid);

    const createCap = await cliCapture(a, "context", "create", "--name", "story7");
    expect(createCap.code, `create failed: ${createCap.err}`).toBe(0);
    const id = json(createCap).context_id as string;
    expect((await cliCapture(a, "context", "set", "--id", id, "--text", "precious content", "--expect", "0")).code).toBe(0);

    // The recovery code is printed to stderr, exactly once, at creation —
    // never logged anywhere else, never emitted as structured JSON (see
    // printRecoveryCode in cli.ts). Extract it from that one note.
    const codeMatch = createCap.err.match(/^ {4}(AMSC1-\S+)$/m);
    expect(codeMatch, `no recovery code found in create output:\n${createCap.err}`).toBeTruthy();
    const recoveryCode = codeMatch![1];

    // Total local state loss: a brand new machine identity (fresh home ==
    // fresh installation, fresh keys) that happens to log back in as the
    // same GitHub user — this is deliberately NOT the same installation, so
    // the server holds no envelope for it yet.
    const b = home("s7-b-after-loss");
    await registerDev(b, uid);

    const beforeImport = await cliCapture(b, "context", "get", "--id", id);
    expect(beforeImport.code).toBe(1); // owner role is intact server-side, but no local/delivered key yet
    expect(beforeImport.err).toMatch(/no local key|older epoch/);

    const importRes = await cliCapture(b, "context", "import-recovery", "--id", id, "--code", recoveryCode);
    expect(importRes.code, `import-recovery failed: ${importRes.err}`).toBe(0);

    const afterImport = json(await cliCapture(b, "context", "get", "--id", id));
    expect(afterImport.text).toBe("precious content");
  });

  story("8. send an encrypted message to a saved contact; recipient decrypts; receive --ack consumes it once", async () => {
    const a = home("s8-a");
    const b = home("s8-b");
    const aSession = await registerDev(a, freshUid());
    await registerDev(b, freshUid());

    // A needs B's card (public key + session id) to address and encrypt to
    // B — the real card-exchange path, mirroring story 2.
    const bCard = await getCard(b);
    expect(await cliAs(a, "contact", "add", "bob", "--card", bCard.card)).toBe(0);

    // B must explicitly allow A before A can reach B (see story 9) — the
    // default policy set at registration allows only the account's own
    // github user id.
    expect((await cliCapture(b, "policy", "set", "--mode", "git_user", "--allow", String(aSession.github_user_id))).code).toBe(0);

    const sendRes = await cliCapture(a, "send", "--to", "bob", "--text", "hello over the real wire");
    expect(sendRes.code, `send failed: ${sendRes.err}`).toBe(0);
    expect(json(sendRes).encrypted).toBe(true);

    const recv1 = json(await cliCapture(b, "receive", "--ack"));
    expect(recv1.messages).toHaveLength(1);
    expect(recv1.messages[0]).toMatchObject({ text: "hello over the real wire", encrypted: true });

    // Consumed once: the local read cursor advanced, so the same page is not
    // handed back again.
    const recv2 = json(await cliCapture(b, "receive"));
    expect(recv2.messages).toHaveLength(0);
  });

  story("9. default-deny: an unauthorised sender is refused", async () => {
    const b = home("s9-b");
    const c = home("s9-c");
    const bSession = await registerDev(b, freshUid());
    await registerDev(c, freshUid());
    // B never allow-lists C.

    const sendRes = await cliCapture(
      c,
      "send",
      "--to",
      String(bSession.session_id),
      "--text",
      "uninvited",
      "--plaintext",
      "--i-understand-the-risk",
    );
    expect(sendRes.code).toBe(1);
    expect(sendRes.err).toContain("not_whitelisted");
  });

  story("10. feedback submits and reports remaining quota", async () => {
    const d = home("s10-d");
    await registerDev(d, freshUid());

    const res = await cliCapture(d, "feedback", "--text", "the acceptance suite says hi", "--kind", "bug");
    expect(res.code, `feedback failed: ${res.err}`).toBe(0);
    const body = json(res);
    expect(body.feedback_id).toBeTruthy();
    expect(body.kind).toBe("bug");
    // Free/verified accounts get 10/day (see api_cost.go DefaultLimits /
    // FreeLimits); a fresh account's first submission leaves 9.
    expect(body.remaining_today).toBe(9);
  });
});
