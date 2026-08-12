import { describe, it, expect } from "vitest";
import { interpretAclProbe } from "../src/installation.js";

// The bug this pins: a check that never ran was reported as a check that
// failed. On Windows CI the installation-key probe printed
//   error: installation key Windows ACL or owner is unsafe
// with an EMPTY detail — and an empty detail is the tell, because the
// PowerShell script always prints owner= and rules= before exiting 2 or 3.
// Nothing was wrong with the ACL; powershell.exe had simply not delivered a
// verdict in time. Every command that reads the installation key then failed,
// which on Windows includes all of `agentmsg context`.
describe("interpretAclProbe", () => {
  it("exit 0 is safe", () => {
    expect(interpretAclProbe({ status: 0 })).toEqual({ kind: "safe" });
  });

  it("a bad owner (exit 2) is unsafe, and keeps what the script reported", () => {
    const v = interpretAclProbe({ status: 2, stdout: "owner=S-1-5-21-9 rules=S-1-5-21-9" });
    expect(v.kind).toBe("unsafe");
    expect(v).toHaveProperty("detail", "owner=S-1-5-21-9 rules=S-1-5-21-9");
  });

  it("a bad rule (exit 3) is unsafe", () => {
    expect(interpretAclProbe({ status: 3, stdout: "owner=me rules=me,everyone" }).kind).toBe("unsafe");
  });

  // The regression. spawnSync reports a timeout as status null; the old code
  // tested `status !== 0` and so called this unsafe.
  it("a timeout is indeterminate, NOT unsafe", () => {
    const v = interpretAclProbe({ status: null, error: new Error("spawnSync ETIMEDOUT"), stdout: "", stderr: "" });
    expect(v.kind).toBe("indeterminate");
    expect(v).toHaveProperty("detail", expect.stringContaining("ETIMEDOUT"));
  });

  it("powershell.exe missing is indeterminate, NOT unsafe", () => {
    expect(interpretAclProbe({ status: null, error: new Error("spawnSync ENOENT") }).kind).toBe("indeterminate");
  });

  it("names a cause even when the failure arrived with no error object", () => {
    const v = interpretAclProbe({ status: null });
    expect(v.kind).toBe("indeterminate");
    expect(v).toHaveProperty("detail", "no exit status");
  });

  // The exact shape seen in CI: no status, no output at all. This must never
  // again be reported as a statement about the ACL.
  it("the observed CI failure is not reported as an ACL fault", () => {
    const v = interpretAclProbe({ status: null, stdout: "", stderr: "" });
    expect(v.kind).not.toBe("unsafe");
  });
});
