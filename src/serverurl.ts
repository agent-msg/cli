// SEC-01: the server URL decides where GitHub tokens and session bearer tokens
// are sent. Validate it hard so a malicious --server / AGENTMSG_SERVER can't
// exfiltrate credentials. HTTPS only by default; plain HTTP only to loopback and
// only when the caller explicitly opts in.

const LOOPBACK = new Set(["localhost", "127.0.0.1", "::1", "[::1]"]);

function isLoopback(hostname: string): boolean {
  // URL.hostname strips the brackets from [::1]; handle both forms.
  return LOOPBACK.has(hostname) || hostname === "::1";
}

/**
 * Parse and normalize a server URL, throwing a clear error if it is unsafe.
 * Returns origin + pathname with any trailing slash removed.
 */
export function normalizeServerUrl(input: string, allowInsecureHttp: boolean): string {
  let u: URL;
  try {
    u = new URL(input);
  } catch {
    throw new Error(`invalid server URL: ${JSON.stringify(input)}`);
  }
  if (u.username || u.password) {
    throw new Error("server URL must not contain userinfo (user:pass@) credentials");
  }
  if (u.protocol !== "https:" && u.protocol !== "http:") {
    throw new Error(`server URL must use https (got ${u.protocol.replace(":", "")})`);
  }
  if (u.protocol === "http:") {
    if (!allowInsecureHttp) {
      throw new Error("refusing to send credentials over plain http; use https (or --allow-insecure-http for a local dev server)");
    }
    if (!isLoopback(u.hostname)) {
      throw new Error("--allow-insecure-http only permits loopback hosts (localhost, 127.0.0.1, ::1)");
    }
  }
  // Normalize: drop a trailing slash on the path so path concatenation is clean.
  const path = u.pathname.replace(/\/$/, "");
  return u.origin + path;
}
