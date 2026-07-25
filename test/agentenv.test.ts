import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { agentSessionProfile, detectAgentRuntime, suggestedSessionName } from "../src/session.js";

// Every var these tests touch, cleared before each case so one test cannot leak
// an agent identity into the next.
const TOUCHED = [
  "AGENTMSG_SESSION",
  "CLAUDE_CODE_SESSION_ID",
  "CLAUDECODE",
  "AI_AGENT",
  "CODEX_THREAD_ID",
  "CODEX_SANDBOX",
  "CURSOR_SESSION_ID",
  "CURSOR_TRACE_ID",
  "OPENCLAW_CLI",
  "OPENCLAW_DEBUG_PROXY_SESSION_ID",
  "AIDER_CONVERSATION_ID",
];
const saved: Record<string, string | undefined> = {};
beforeEach(() => {
  for (const k of TOUCHED) {
    saved[k] = process.env[k];
    delete process.env[k];
  }
});
afterEach(() => {
  for (const k of TOUCHED) {
    if (saved[k] === undefined) delete process.env[k];
    else process.env[k] = saved[k]!;
  }
});

describe("agentSessionProfile: sniffing session ids across agent CLIs", () => {
  it("uses AGENTMSG_SESSION first — the escape hatch any harness can set", () => {
    process.env.AGENTMSG_SESSION = "mine";
    process.env.CLAUDE_CODE_SESSION_ID = "theirs";
    const a = agentSessionProfile();
    delete process.env.AGENTMSG_SESSION;
    expect(a).not.toBe(agentSessionProfile()); // the two sources differ
  });

  // Verified on this machine: Claude Code exports this.
  it("picks up Claude Code's session id", () => {
    process.env.CLAUDE_CODE_SESSION_ID = "abc";
    expect(agentSessionProfile()).toMatch(/^s-[0-9a-f]{12}$/);
  });

  // Codex has no CODEX_SESSION_ID; its conversation handle is CODEX_THREAD_ID.
  // The pattern sniffer is what saves us from having to know that in advance.
  it("sniffs a THREAD_ID from a known agent prefix", () => {
    process.env.CODEX_THREAD_ID = "t-42";
    expect(agentSessionProfile()).toMatch(/^s-[0-9a-f]{12}$/);
  });

  it("sniffs a CONVERSATION_ID too", () => {
    process.env.AIDER_CONVERSATION_ID = "c-1";
    expect(agentSessionProfile()).toMatch(/^s-[0-9a-f]{12}$/);
  });

  it("gives different profiles for different ids, and a stable one per id", () => {
    process.env.CODEX_THREAD_ID = "one";
    const a = agentSessionProfile();
    expect(agentSessionProfile()).toBe(a);
    process.env.CODEX_THREAD_ID = "two";
    expect(agentSessionProfile()).not.toBe(a);
  });

  // A per-request id would mint a brand-new identity on every single command,
  // forcing a re-register each time. Those must never be sniffed.
  it("ignores debug/proxy/trace ids that change per call", () => {
    process.env.OPENCLAW_DEBUG_PROXY_SESSION_ID = "random-per-capture";
    expect(agentSessionProfile()).toBeUndefined();
    process.env.CURSOR_TRACE_ID = "per-request";
    expect(agentSessionProfile()).toBeUndefined();
  });

  // Found the hard way: Claude Code really exports CLAUDE_CODE_CHILD_SESSION=1.
  // It matches the *_SESSION shape but is a boolean ABOUT the session, not an id
  // OF it — every session would hash "1" and collapse onto one home again.
  it("ignores CLAUDE_CODE_CHILD_SESSION=1, a flag that only looks like an id", () => {
    process.env.CLAUDE_CODE_CHILD_SESSION = "1";
    const r = agentSessionProfile();
    delete process.env.CLAUDE_CODE_CHILD_SESSION;
    expect(r).toBeUndefined();
  });

  it("ignores boolean-ish values whatever the variable is called", () => {
    for (const v of ["1", "0", "true", "false", "none"]) {
      process.env.CODEX_THREAD_ID = v;
      expect(agentSessionProfile()).toBeUndefined();
    }
  });

  it("ignores session vars from non-agent programs (terminals, tmux)", () => {
    process.env.ITERM_SESSION_ID = "w0t0p0";
    process.env.TERM_SESSION_ID = "xyz";
    const r = agentSessionProfile();
    delete process.env.ITERM_SESSION_ID;
    delete process.env.TERM_SESSION_ID;
    expect(r).toBeUndefined(); // a new terminal tab is not a new identity
  });

  it("returns undefined in a plain human shell", () => {
    expect(agentSessionProfile()).toBeUndefined();
  });
});

describe("detectAgentRuntime: are we inside an agent at all?", () => {
  it("names Claude Code", () => {
    process.env.CLAUDECODE = "1";
    expect(detectAgentRuntime()).toMatch(/claude/i);
  });

  // The case that motivated all this: openclaw marks its children but exposes
  // no session id, so we can detect the risk without being able to fix it.
  it("names openclaw, which exposes no session id", () => {
    process.env.OPENCLAW_CLI = "1";
    expect(detectAgentRuntime()).toMatch(/openclaw/i);
    expect(agentSessionProfile()).toBeUndefined(); // detected, but unidentifiable
  });

  it("names codex via its sandbox marker", () => {
    process.env.CODEX_SANDBOX = "seatbelt";
    expect(detectAgentRuntime()).toMatch(/codex/i);
  });

  it("falls back to the generic AI_AGENT marker", () => {
    process.env.AI_AGENT = "something-new";
    expect(detectAgentRuntime()).toBeTruthy();
  });

  it("returns undefined in a plain human shell", () => {
    expect(detectAgentRuntime()).toBeUndefined();
  });
});

describe("suggestedSessionName: a value the human can paste", () => {
  it("is a safe path segment", () => {
    expect(suggestedSessionName()).toMatch(/^[A-Za-z0-9._-]+$/);
  });

  it("differs between calls, so two sessions don't get the same suggestion", () => {
    expect(suggestedSessionName()).not.toBe(suggestedSessionName());
  });
});
