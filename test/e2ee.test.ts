import { describe, it, expect, beforeAll, afterAll, beforeEach, afterEach } from "vitest";
import { createServer, Server } from "node:http";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { run } from "../src/cli.js";
import { generateKeypair, open } from "../src/crypto.js";

// A stub server modelling the E2EE contract: it stores whatever `text`/`enc` it
// receives (like the real server, which never decrypts) and serves it back.
let server: Server;
let base: string;
const store: { to: string; text: string; enc?: string }[] = [];

beforeAll(async () => {
  server = createServer((req, res) => {
    let body = "";
    req.on("data", (c) => (body += c));
    req.on("end", () => {
      const j = (out: unknown, code = 200) => {
        res.writeHead(code, { "Content-Type": "application/json" });
        res.end(JSON.stringify(out));
      };
      if (req.url === "/v1/register") return j({ session_id: "sid_" + store.length, token: "tok", github_login: "u", github_user_id: "1" });
      if (req.url === "/v1/messages") {
        const m = JSON.parse(body);
        store.push({ to: m.to, text: m.text, enc: m.enc });
        return j({ msg_id: "m1", seq: store.length });
      }
      if (req.url?.startsWith("/v1/inbox")) {
        return j({
          messages: store.map((m, i) => ({ seq: i + 1, msg_id: "m", from: "sender", text: m.text, enc: m.enc })),
          cursor: 0,
        });
      }
      j({}, 404);
    });
  });
  await new Promise<void>((r) => server.listen(0, r));
  const a = server.address();
  base = `http://127.0.0.1:${typeof a === "object" && a ? a.port : 0}`;
});
afterAll(() => new Promise<void>((r) => server.close(() => r())));

let bobHome: string, aliceHome: string, aliceKeys: { publicKey: string; privateKey: string };
beforeEach(async () => {
  store.length = 0;
  bobHome = mkdtempSync(join(tmpdir(), "e2ee-bob-"));
  aliceHome = mkdtempSync(join(tmpdir(), "e2ee-alice-"));
  aliceKeys = await generateKeypair();
  process.env.AGENTMSG_SERVER = base;
});
afterEach(() => {
  rmSync(bobHome, { recursive: true, force: true });
  rmSync(aliceHome, { recursive: true, force: true });
  delete process.env.AGENTMSG_SERVER;
});

async function bob(...argv: string[]) {
  process.env.AGENTMSG_HOME = bobHome;
  const code = await run(argv);
  delete process.env.AGENTMSG_HOME;
  return code;
}

describe("E2EE end-to-end through the CLI", () => {
  it("encrypts to a saved contact so the server never sees plaintext, and the recipient decrypts", async () => {
    const secret = "deploy key is in the vault 秘密 🔐";
    await bob("register", "--dev-user", "99", "--dev-login", "bob", "--allow-insecure-http");
    // Bob saves Alice's address card (session id + public key).
    await bob("contact", "add", "alice", "--sid", "alice_sid", "--pubkey", aliceKeys.publicKey, "--user", "42");
    await bob("send", "--to", "alice", "--text", secret);

    // The server stored ciphertext, flagged box1, addressed to Alice's sid.
    expect(store).toHaveLength(1);
    expect(store[0].enc).toBe("box1");
    expect(store[0].to).toBe("alice_sid");
    expect(store[0].text).not.toContain("vault");
    expect(store[0].text).not.toContain(secret);

    // Only Alice's private key recovers the plaintext.
    const plain = await open(store[0].text, aliceKeys.publicKey, aliceKeys.privateKey);
    expect(plain).toBe(secret);
  });

  it("fails closed (no send) when the recipient's public key is unknown", async () => {
    await bob("register", "--dev-user", "99", "--dev-login", "bob", "--allow-insecure-http");
    // A raw session id with no saved contact => no public key => refuse to send.
    const code = await bob("send", "--to", "raw_sid", "--text", "hello in the clear");
    expect(code).toBe(1);
    expect(store).toHaveLength(0);
  });
});
