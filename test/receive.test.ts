import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { createServer, Server } from "node:http";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { run } from "../src/cli.js";

// Stub inbox server: /v1/inbox?after=N returns plaintext messages with seq > N
// plus the ack cursor; /v1/inbox/ack advances that cursor. The `inbox` array and
// `ackCursor` are controlled by each test.
let server: Server, base: string;
let inbox: { seq: number; msg_id: string; from: string; text: string }[];
let ackCursor: number;
let streamClients: { after: number; res: any }[];

function writeSse(res: any, m: { seq: number; msg_id: string; from: string; text: string }) {
  res.write(`event: message\n`);
  res.write(`data: ${JSON.stringify(m)}\n\n`);
}

beforeEach(async () => {
  inbox = [];
  ackCursor = 0;
  streamClients = [];
  server = createServer((req, res) => {
    const u = new URL(req.url || "/", "http://x");
    if (u.pathname === "/v1/inbox/stream") {
      const after = parseInt(u.searchParams.get("after") || "0", 10);
      res.writeHead(200, { "Content-Type": "text/event-stream", "Cache-Control": "no-cache" });
      for (const m of inbox.filter((msg) => msg.seq > after)) writeSse(res, m);
      streamClients.push({ after, res });
      req.on("close", () => {
        streamClients = streamClients.filter((c) => c.res !== res);
      });
      return;
    }
    let b = "";
    req.on("data", (c) => (b += c));
    req.on("end", () => {
      if (u.pathname === "/v1/register") {
        return res.end(JSON.stringify({ session_id: "s", token: "t", github_login: "u", github_user_id: "1" }));
      }
      if (u.pathname === "/v1/inbox") {
        const after = parseInt(u.searchParams.get("after") || "0", 10);
        return res.end(JSON.stringify({ messages: inbox.filter((m) => m.seq > after), cursor: ackCursor }));
      }
      if (u.pathname === "/v1/inbox/ack") {
        ackCursor = JSON.parse(b).seq;
        return res.end("{}");
      }
      res.end("{}");
    });
  });
  await new Promise<void>((r) => server.listen(0, r));
  const a = server.address();
  base = `http://127.0.0.1:${typeof a === "object" && a ? a.port : 0}`;
});
afterEach(
  () =>
    new Promise<void>((r) => {
      for (const c of streamClients) c.res.end();
      streamClients = [];
      server.close(() => r());
    }),
);

let home: string;
beforeEach(() => (home = mkdtempSync(join(tmpdir(), "amsg-rcv-"))));
afterEach(() => rmSync(home, { recursive: true, force: true }));

// Run a CLI command capturing the emitted JSON on stdout.
async function cliOut(...argv: string[]): Promise<{ code: number; out: any }> {
  const chunks: string[] = [];
  const orig = process.stdout.write.bind(process.stdout);
  (process.stdout as any).write = (s: any) => (chunks.push(String(s)), true);
  process.env.AGENTMSG_HOME = home;
  process.env.AGENTMSG_SERVER = base;
  let code = 0;
  try {
    code = await run(argv);
  } finally {
    (process.stdout as any).write = orig;
    delete process.env.AGENTMSG_HOME;
    delete process.env.AGENTMSG_SERVER;
  }
  const out = chunks.length ? JSON.parse(chunks.join("")) : null;
  return { code, out };
}

const seqs = (o: any) => (o?.messages ?? []).map((m: any) => m.seq);
const pushInbox = (m: { seq: number; msg_id: string; from: string; text: string }) => {
  inbox.push(m);
  for (const c of streamClients) if (m.seq > c.after) writeSse(c.res, m);
};
async function waitForStreamClient() {
  for (let i = 0; i < 100; i++) {
    if (streamClients.length > 0) return;
    await new Promise<void>((resolve) => setTimeout(resolve, 10));
  }
  throw new Error("stream client did not connect");
}

describe("receive: unread-since-ack by default", () => {
  beforeEach(async () => {
    await cliOut("register", "--dev-user", "99", "--allow-insecure-http");
    inbox = [
      { seq: 1, msg_id: "m1", from: "x", text: "one" },
      { seq: 2, msg_id: "m2", from: "x", text: "two" },
      { seq: 3, msg_id: "m3", from: "x", text: "three" },
    ];
  });

  it("shows everything when nothing has been acked yet", async () => {
    const { out } = await cliOut("receive");
    expect(seqs(out)).toEqual([1, 2, 3]);
  });

  it("--ack advances the read cursor so the next default receive is empty", async () => {
    const first = await cliOut("receive", "--ack");
    expect(seqs(first.out)).toEqual([1, 2, 3]);

    const second = await cliOut("receive"); // default: only unread
    expect(seqs(second.out)).toEqual([]); // the acked messages are consumed
  });

  it("a message that arrives after an ack shows up alone on the next receive", async () => {
    await cliOut("receive", "--ack"); // consume 1-3
    inbox.push({ seq: 4, msg_id: "m4", from: "x", text: "four" });

    const { out } = await cliOut("receive");
    expect(seqs(out)).toEqual([4]);
  });

  it("--all shows full history regardless of the cursor", async () => {
    await cliOut("receive", "--ack"); // cursor now at 3
    const { out } = await cliOut("receive", "--all");
    expect(seqs(out)).toEqual([1, 2, 3]);
  });

  it("--after N overrides the cursor with an explicit start", async () => {
    await cliOut("receive", "--ack"); // cursor at 3
    const { out } = await cliOut("receive", "--after", "1");
    expect(seqs(out)).toEqual([2, 3]);
  });

  it("peeking without --ack does not consume (cursor unchanged)", async () => {
    await cliOut("receive"); // no ack
    const { out } = await cliOut("receive"); // still unread
    expect(seqs(out)).toEqual([1, 2, 3]);
  });

  it("--watch streams unread messages over SSE and exits after --max", async () => {
    const { out } = await cliOut("receive", "--watch", "--max", "1");
    expect(out.message.seq).toBe(1);
    expect(out.cursor).toBe(1);
  });

  it("--watch --ack advances the read cursor for streamed messages", async () => {
    const { out } = await cliOut("receive", "--watch", "--ack", "--max", "1");
    expect(out.message.seq).toBe(1);
    expect(ackCursor).toBe(1);
  });

  it("--watch waits for live messages when the backlog is empty", async () => {
    inbox = [];
    const pending = cliOut("receive", "--watch", "--ack", "--after", "3", "--max", "1");
    await waitForStreamClient();
    pushInbox({ seq: 4, msg_id: "m4", from: "x", text: "four" });
    const { out } = await pending;
    expect(out.message.seq).toBe(4);
    expect(ackCursor).toBe(4);
  });
});
