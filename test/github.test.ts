import { createServer, type Server } from "node:http";
import { afterEach, describe, expect, it } from "vitest";
import { githubIdentity } from "../src/github.js";

let server: Server | undefined;

afterEach(async () => {
  if (server) await new Promise<void>((resolve) => server!.close(() => resolve()));
  server = undefined;
});

async function serve(body: unknown, status = 200): Promise<string> {
  server = createServer((_req, res) => {
    res.writeHead(status, { "Content-Type": "application/json" });
    res.end(JSON.stringify(body));
  });
  await new Promise<void>((resolve) => server!.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  return `http://127.0.0.1:${typeof address === "object" && address ? address.port : 0}`;
}

describe("GitHub identity binding", () => {
  it("returns the immutable numeric id and login", async () => {
    const base = await serve({ id: 424242, login: "alice" });
    await expect(githubIdentity("token", { base })).resolves.toEqual({
      githubUserId: "424242",
      githubLogin: "alice",
    });
  });

  it("fails closed on an incomplete identity response", async () => {
    const base = await serve({ login: "alice" });
    await expect(githubIdentity("token", { base })).rejects.toThrow(/incomplete/);
  });
});
