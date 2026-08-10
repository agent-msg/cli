// Branded identifier types for the context/sharing paths (see rework-plan.md
// R2/R4b/R7/R9). Five bugs in a row were the same shape: sessionId,
// installationId, githubUserId (and principalId) are all plain strings that
// are NOT interchangeable, passed positionally, with nothing telling the
// compiler apart which is which — so a value of one kind silently flowed
// into a parameter expecting another. Branding turns that class of mistake
// into a compile error at the exact boundaries where it has actually bitten:
// Address (contacts.ts), the context-membership/envelope calls (client.ts),
// and the pending-answer path (cli.ts).
//
// Deliberately NOT applied to every string in the codebase — e.g. Session's
// fields stay plain strings, since Session is used far more broadly than the
// sharing paths this defect class lives in, and messaging (sessionId,
// publicKey) is unaffected by this: branding narrows a string, so any
// existing `string`-typed parameter (like SendInput.to) keeps accepting a
// branded value with no code changes.

export type InstallationId = string & { readonly __brand: "InstallationId" };
export type SessionId = string & { readonly __brand: "SessionId" };
export type GitHubUserId = string & { readonly __brand: "GitHubUserId" };

/**
 * Constructors for the boundaries where a raw string legitimately enters
 * from JSON (a server response) or user input (a CLI flag, a pasted address
 * card) and needs to become one of the branded ids above. Intentionally
 * trivial — they exist to mark *where* an unchecked string becomes a typed
 * id, not to validate its shape.
 */
export function asInstallationId(s: string): InstallationId {
  return s as InstallationId;
}
export function asSessionId(s: string): SessionId {
  return s as SessionId;
}
export function asGitHubUserId(s: string): GitHubUserId {
  return s as GitHubUserId;
}
