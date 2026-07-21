import { describe, it, expect } from "vitest";
import { normalizeServerUrl } from "../src/serverurl.js";

describe("normalizeServerUrl (SEC-01: don't leak credentials to arbitrary origins)", () => {
  it("accepts https and normalizes it", () => {
    expect(normalizeServerUrl("https://msg.agentmsg.org", false)).toBe("https://msg.agentmsg.org");
    expect(normalizeServerUrl("https://msg.agentmsg.org/", false)).toBe("https://msg.agentmsg.org");
  });

  it("rejects plain http by default (credential theft over the wire)", () => {
    expect(() => normalizeServerUrl("http://attacker.example", false)).toThrow(/https/i);
  });

  it("rejects non-http(s) schemes", () => {
    for (const u of ["file:///etc/passwd", "ftp://x", "javascript:alert(1)", "ws://x"]) {
      expect(() => normalizeServerUrl(u, false)).toThrow();
    }
  });

  it("rejects embedded credentials in the URL", () => {
    expect(() => normalizeServerUrl("https://user:pass@evil.example", false)).toThrow(/credential|userinfo|user/i);
  });

  it("rejects unparseable input", () => {
    expect(() => normalizeServerUrl("not a url", false)).toThrow();
    expect(() => normalizeServerUrl("", false)).toThrow();
  });

  it("allows loopback http ONLY when insecure http is explicitly enabled", () => {
    // Disallowed without the flag...
    expect(() => normalizeServerUrl("http://localhost:8080", false)).toThrow(/https/i);
    // ...allowed with it, but only for loopback hosts.
    expect(normalizeServerUrl("http://localhost:8080", true)).toBe("http://localhost:8080");
    expect(normalizeServerUrl("http://127.0.0.1:8090", true)).toBe("http://127.0.0.1:8090");
    expect(normalizeServerUrl("http://[::1]:8090", true)).toBe("http://[::1]:8090");
  });

  it("even with the insecure flag, non-loopback http is refused", () => {
    expect(() => normalizeServerUrl("http://attacker.example", true)).toThrow(/loopback|localhost/i);
    expect(() => normalizeServerUrl("http://10.0.0.5", true)).toThrow(/loopback|localhost/i);
  });

  it("https to a loopback host is fine without the flag", () => {
    expect(normalizeServerUrl("https://localhost:8443", false)).toBe("https://localhost:8443");
  });
});
