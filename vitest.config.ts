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
  },
});
