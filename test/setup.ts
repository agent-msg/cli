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
