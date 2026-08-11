import { defineConfig } from "vitest/config";
// Tests intentionally exercise process-wide environment variables such as
// AGENTMSG_HOME. Running files in parallel lets one fixture's temporary home
// leak into another (especially on Windows), producing nondeterministic
// contacts.json corruption and registration failures.
export default defineConfig({
  test: {
    include: ["test/**/*.test.ts"],
    setupFiles: ["test/setup.ts"],
    fileParallelism: false,
    // These are not unit tests with mocked I/O: each one registers for real,
    // writes key material through an fsync'd atomic write, and talks HTTP to an
    // in-process server. That costs ~40ms per test on a developer Mac and
    // ~650ms on a Windows CI runner — where fsync is FlushFileBuffers and every
    // file created in the temp directory is scanned as it is written.
    //
    // The default 5s therefore leaves under 8x headroom on Windows, which the
    // runner's own jitter exceeds: the same unchanged test measured 535ms,
    // 1884ms, and >5000ms (a CI failure) across three runs of the same code on
    // 2026-08-10. The timeout was catching a slow shared runner, not a defect.
    //
    // 30s keeps a genuine hang failing the run instead of hanging the job,
    // while sitting far above the observed worst case. Raise the cost of a test
    // — not this number — if a test ever legitimately approaches it.
    testTimeout: 30_000,
  },
});
