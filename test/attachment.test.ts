import { describe, it, expect, beforeAll, afterAll, beforeEach, afterEach } from "vitest";
import { createServer, Server } from "node:http";
import { mkdtempSync, rmSync, writeFileSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createHash } from "node:crypto";
import { run } from "../src/cli.js";
import { generateKeypair, sealBytes, openBytes } from "../src/crypto.js";
import { SessionStore } from "../src/session.js";

// Stub server modelling the two-phase attachment contract: /v1/messages returns
// upload tickets; the client PUTs ciphertext to them; /commit finalizes; and
// /v1/attachments/... serves the stored bytes back. It NEVER decrypts — it holds
// only the opaque ciphertext the client uploads. Bodies are read as raw Buffers
// so binary ciphertext round-trips byte-exact.
let server: Server;
let base: string;
let lastSend: { to: string; text: string; enc?: string; attachments?: { filename: string; mime: string; bytes: number; sha256: string }[] };
let uploaded: Record<string, Buffer>; // PUT bodies captured, by filename
let served: Record<string, Buffer>; // bytes to hand back on download, by filename
let committed: boolean;

beforeAll(async () => {
  server = createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on("data", (c) => chunks.push(c as Buffer));
    req.on("end", () => {
      const raw = Buffer.concat(chunks);
      const url = req.url || "/";
      const j = (out: unknown, code = 200) => {
        res.writeHead(code, { "Content-Type": "application/json" });
        res.end(JSON.stringify(out));
      };
      if (url === "/v1/register") return j({ session_id: "sid", token: "tok", github_login: "u", github_user_id: "1" });
      if (url === "/v1/messages" && req.method === "POST") {
        lastSend = JSON.parse(raw.toString("utf8"));
        if (lastSend.attachments && lastSend.attachments.length) {
          return j({
            msg_id: "M1",
            uploads: lastSend.attachments.map((a) => ({ filename: a.filename, put_url: base + "/upload/M1/" + encodeURIComponent(a.filename) })),
          });
        }
        return j({ msg_id: "M1", seq: 1 });
      }
      if (url.startsWith("/upload/") && req.method === "PUT") {
        uploaded[decodeURIComponent(url.split("/").pop() || "")] = raw;
        res.writeHead(200);
        return res.end();
      }
      if (/^\/v1\/messages\/[^/]+\/commit$/.test(url) && req.method === "POST") {
        committed = true;
        return j({ msg_id: "M1", seq: 1 });
      }
      if (url.startsWith("/v1/attachments/")) {
        const bytes = served[decodeURIComponent(url.split("/").pop() || "")];
        if (!bytes) {
          res.writeHead(404);
          return res.end();
        }
        res.writeHead(200, { "Content-Type": "application/octet-stream" });
        return res.end(bytes);
      }
      j({}, 404);
    });
  });
  await new Promise<void>((r) => server.listen(0, r));
  const a = server.address();
  base = `http://127.0.0.1:${typeof a === "object" && a ? a.port : 0}`;
});
afterAll(() => new Promise<void>((r) => server.close(() => r())));

let bobHome: string;
beforeEach(() => {
  lastSend = { to: "", text: "" };
  uploaded = {};
  served = {};
  committed = false;
  bobHome = mkdtempSync(join(tmpdir(), "amsg-att-"));
  process.env.AGENTMSG_SERVER = base;
});
afterEach(() => {
  rmSync(bobHome, { recursive: true, force: true });
  delete process.env.AGENTMSG_SERVER;
  delete process.env.AGENTMSG_HOME;
});

async function bob(...argv: string[]) {
  process.env.AGENTMSG_HOME = bobHome;
  return run(argv);
}

describe("byte-level sealing", () => {
  it("round-trips arbitrary bytes and rejects the wrong key", async () => {
    const kp = await generateKeypair();
    const other = await generateKeypair();
    const data = new Uint8Array([0, 1, 2, 255, 254, 128, 42, 7]);
    const ct = await sealBytes(data, kp.publicKey);
    expect(Buffer.from(ct).equals(Buffer.from(data))).toBe(false); // it's ciphertext
    const back = await openBytes(ct, kp.publicKey, kp.privateKey);
    expect(Buffer.from(back).equals(Buffer.from(data))).toBe(true);
    await expect(openBytes(ct, other.publicKey, other.privateKey)).rejects.toThrow();
  });
});

describe("CLI attachments (E2EE two-phase)", () => {
  it("seals each file before upload, so the server only ever stores ciphertext", async () => {
    const recip = await generateKeypair();
    const plaintext = Buffer.from("secret file contents 机密 🔐\nline2\n");
    const fpath = join(bobHome, "data.txt");
    writeFileSync(fpath, plaintext);

    await bob("register", "--dev-user", "99", "--dev-login", "bob", "--allow-insecure-http");
    await bob("contact", "add", "alice", "--sid", "alice_sid", "--pubkey", recip.publicKey, "--user", "42");
    const code = await bob("send", "--to", "alice", "--text", "see attached", "--file", fpath);
    expect(code).toBe(0);

    // The send declared an encrypted attachment.
    expect(lastSend.enc).toBe("box1");
    expect(lastSend.attachments).toHaveLength(1);
    expect(lastSend.attachments![0].filename).toBe("data.txt");

    // The uploaded bytes are CIPHERTEXT — not the plaintext — and only the
    // recipient's private key can open them.
    const ct = uploaded["data.txt"];
    expect(ct).toBeDefined();
    expect(ct.equals(plaintext)).toBe(false);
    expect(ct.toString("utf8")).not.toContain("secret file");
    const opened = await openBytes(new Uint8Array(ct), recip.publicKey, recip.privateKey);
    expect(Buffer.from(opened).equals(plaintext)).toBe(true);

    // Declared bytes/sha256 describe the ciphertext, and commit was called.
    expect(lastSend.attachments![0].bytes).toBe(ct.length);
    expect(lastSend.attachments![0].sha256).toBe(createHash("sha256").update(ct).digest("hex"));
    expect(committed).toBe(true);
  });

  it("downloads and decrypts an attachment sealed to this session", async () => {
    await bob("register", "--dev-user", "99", "--dev-login", "bob", "--allow-insecure-http");
    const sess = new SessionStore(bobHome).load()!;
    const payload = Buffer.from([104, 105, 0, 1, 255, 200, 42]); // arbitrary binary
    served["doc.bin"] = Buffer.from(await sealBytes(payload, sess.publicKey));

    const out = join(bobHome, "recovered.bin");
    const code = await bob("download", "--msg", "M1", "--file", "doc.bin", "--out", out);
    expect(code).toBe(0);
    expect(readFileSync(out).equals(payload)).toBe(true);
  });

  it("refuses to attach a file when the recipient's public key is unknown", async () => {
    const fpath = join(bobHome, "x.txt");
    writeFileSync(fpath, "hi");
    await bob("register", "--dev-user", "99", "--dev-login", "bob", "--allow-insecure-http");
    const code = await bob("send", "--to", "raw_sid", "--file", fpath);
    expect(code).toBe(1);
    expect(Object.keys(uploaded)).toHaveLength(0);
    expect(committed).toBe(false);
  });
});
