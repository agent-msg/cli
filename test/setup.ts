// The suite runs inside an agent session (CI, or a Claude Code/Codex/openclaw
// shell), so that harness's own env vars are present. They would auto-derive a
// profile and push every test's state into a subdirectory of AGENTMSG_HOME.
//
// Clear them by PATTERN, not by a fixed list: the list would silently rot as
// harnesses add variables, and the tests would then depend on which agent the
// suite happened to run under. Tests that exercise detection set what they need.
for (const k of Object.keys(process.env)) {
  if (/^(AGENTMSG_(SESSION|PROFILE|HOME|SERVER)|CLAUDE|CLAUDECODE|CODEX|CURSOR|OPENCLAW|AIDER|GEMINI|COPILOT|AMP|CLINE|WINDSURF|DEVIN|GOOSE|OPENHANDS|AI_AGENT)/.test(k)) {
    delete process.env[k];
  }
}
// Tests must never prompt a desktop credential store. The fallback is itself
// security-tested and keeps each test fully isolated in its temporary home.
process.env.AGENTMSG_DISABLE_KEYCHAIN = "1";

import type { Server } from "node:http";

// Close an in-process test HTTP server without inheriting Node 18's slow
// shutdown path. Every fetch() a test makes against these servers keeps its
// socket alive by default; on Node 18, http.Server#close() waits for those
// idle keep-alive sockets to time out (or close on their own) before its
// callback fires, which measured ~5s per close there versus ~0.5ms on
// Node 19+ (https://github.com/nodejs/node/issues/50188 — a change in how
// later Node versions tear down idle connections on close(), not present in
// 18's http implementation). A single test closing one fresh server was
// enough on its own to exceed a 5s test timeout on Node 18, independent of
// anything the CLI itself does.
//
// closeIdleConnections() (added in Node 18.2.0, so available on every
// supported Node 18) forces idle keep-alive sockets shut immediately, so
// close() resolves right away on every supported Node version.
export function closeServer(server: Server): Promise<void> {
  return new Promise<void>((resolve) => {
    server.close(() => resolve());
    server.closeIdleConnections();
  });
}
