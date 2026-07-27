import { createServer, type Server } from "node:http";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { Client } from "../src/client.js";
import { registerGuestFirst } from "../src/guest.js";
import { installationKeyFromSeed } from "../src/installation.js";

const serverURL = process.env.AGENTMSG_GO_SERVER;
const expected = process.env.AGENTMSG_GO_EXPECTED_IDENTITY;
const suite = serverURL && expected ? describe : describe.skip;
let github: Server | undefined;
let githubBase: string | undefined;

suite("real Go server admission integration", () => {
  beforeAll(async () => {
    if (expected !== "github") return;
    github = createServer((req, res) => {
      res.writeHead(200, { "Content-Type": "application/json" });
      if (req.url === "/login/device/code") {
        res.end(JSON.stringify({
          device_code: "device-test",
          user_code: "TEST-CODE",
          verification_uri: "https://github.com/login/device",
          interval: 0,
        }));
      } else {
        res.end(JSON.stringify({ access_token: "42:alice" }));
      }
    });
    await new Promise<void>((resolve) => github!.listen(0, "127.0.0.1", resolve));
    const address = github.address();
    githubBase = `http://127.0.0.1:${typeof address === "object" && address ? address.port : 0}`;
  });

  afterAll(async () => {
    if (github) await new Promise<void>((resolve) => github!.close(() => resolve()));
  });

  it(`completes the ${expected} flow against the Go implementation`, async () => {
    const key = installationKeyFromSeed(Buffer.alloc(32, 23));
    const result = await registerGuestFirst({
      client: new Client(serverURL!),
      installation: key,
      serverOrigin: new URL(serverURL!).origin,
      githubBase,
      note: () => undefined,
    });
    expect(result.identity_type).toBe(expected);
    expect(result.installation_id).toMatch(/^ins_/);
    expect(result.session_id).toMatch(/^ses_/);
    expect(result.address_card.public_key).toBe(key.publicKey);
    if (expected === "github") {
      expect(result).toMatchObject({ verified: true, github_user_id: "42", github_login: "alice" });
    } else {
      expect(result).toMatchObject({ verified: false, identity_type: "guest" });
    }
  }, 30_000);
});
