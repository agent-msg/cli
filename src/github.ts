// GitHub OAuth device flow — run entirely by the CLI to obtain an access token,
// which is then handed to the server's /v1/register (the server verifies it via
// GitHub /user and keys on the immutable numeric id). The client id is public
// (device-flow apps have no secret). onCode surfaces the user code + URL so the
// driving agent can relay them to the human.
export const DEFAULT_CLIENT_ID = "Ov23ctHJCoj1qUKuLaM7";

interface DeviceCode {
  device_code: string;
  user_code: string;
  verification_uri: string;
  interval: number;
}

export interface GithubOptions {
  clientId?: string;
  base?: string; // override github.com for tests
  onCode: (userCode: string, verificationUri: string) => void;
  sleep?: (ms: number) => Promise<void>;
}

const wait = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));

// fetch with a per-request timeout (HARD-01): GitHub, like any host, must not be
// able to hang the CLI indefinitely.
async function fetchTimeout(url: string, init: RequestInit, ms = 20_000): Promise<Response> {
  const ctl = new AbortController();
  const t = setTimeout(() => ctl.abort(), ms);
  try {
    return await fetch(url, { ...init, signal: ctl.signal });
  } finally {
    clearTimeout(t);
  }
}

export async function deviceFlowToken(opts: GithubOptions): Promise<string> {
  const clientId = opts.clientId || DEFAULT_CLIENT_ID;
  const base = opts.base || "https://github.com";
  const sleep = opts.sleep || wait;

  const codeResp = await fetch(`${base}/login/device/code`, {
    method: "POST",
    headers: { Accept: "application/json", "Content-Type": "application/json" },
    body: JSON.stringify({ client_id: clientId, scope: "" }),
  });
  if (!codeResp.ok) throw new Error(`github device code request failed: ${codeResp.status}`);
  const dc = (await codeResp.json()) as DeviceCode;
  opts.onCode(dc.user_code, dc.verification_uri);

  let interval = Math.max(dc.interval || 5, 1);
  const deadline = Date.now() + 15 * 60 * 1000; // GitHub codes last ~15 min
  while (Date.now() < deadline) {
    await sleep(interval * 1000);
    const tokResp = await fetch(`${base}/login/oauth/access_token`, {
      method: "POST",
      headers: { Accept: "application/json", "Content-Type": "application/json" },
      body: JSON.stringify({
        client_id: clientId,
        device_code: dc.device_code,
        grant_type: "urn:ietf:params:oauth:grant-type:device_code",
      }),
    });
    const t = (await tokResp.json()) as { access_token?: string; error?: string };
    if (t.access_token) return t.access_token;
    if (t.error === "authorization_pending") continue;
    if (t.error === "slow_down") {
      interval += 5;
      continue;
    }
    throw new Error(`github authorization failed: ${t.error || "unknown"}`);
  }
  throw new Error("github authorization timed out");
}
