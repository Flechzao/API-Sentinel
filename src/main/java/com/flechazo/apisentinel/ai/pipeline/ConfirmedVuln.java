package com.flechazo.apisentinel.ai.pipeline;

/**
 * A confirmed vulnerability from the final verdict.
 *
 * @param identityProof auth-class findings only: explicit identity evidence —
 *                      which session context was used, whether anonymous
 *                      access was tested, how the returned data was confirmed
 *                      to belong to ANOTHER account. Empty for non-auth
 *                      findings. Enforced by VerdictValidator: auth-class
 *                      confirms with blank identityProof are demoted to
 *                      suspected (identity_not_proven).
 * @param cvss          LLM-assessed CVSS (free text, e.g.
 *                      "8.8 (AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)"); may be "".
 * @param citedExecutionIndex (P0-8) the {@link PayloadResult#executionIndex()}
 *                      this finding is bound to. Binding by index — rather
 *                      than by fuzzy payload-text match — closes the
 *                      "LLM cites a payload it never actually sent" bypass:
 *                      VerdictValidator can now look the result up in O(1)
 *                      and refuse the confirm when the index doesn't exist
 *                      or the referenced result is WAF-blocked / SAFE.
 *                      {@code -1} means "not bound" (legacy or prompt-only
 *                      claims); such confirms fall back to the text-match
 *                      path and are still subjected to the tightened
 *                      similarity threshold there.
 */
public record ConfirmedVuln(
    String type,
    String title,
    String evidence,
    String payloadUsed,
    String response,
    String verifyCommand,
    String identityProof,
    String cvss,
    int citedExecutionIndex
) {
    /** Backward-compatible constructor (no identity proof / CVSS / index). */
    public ConfirmedVuln(String type, String title, String evidence,
                         String payloadUsed, String response, String verifyCommand) {
        this(type, title, evidence, payloadUsed, response, verifyCommand, "", "", -1);
    }

    /** Backward-compatible constructor (8-arg, no index). */
    public ConfirmedVuln(String type, String title, String evidence,
                         String payloadUsed, String response, String verifyCommand,
                         String identityProof, String cvss) {
        this(type, title, evidence, payloadUsed, response, verifyCommand,
                identityProof, cvss, -1);
    }

    /** True when the LLM bound this confirm to a specific payload send.
     *  VerdictValidator uses this to decide whether the index-bound fast
     *  path applies, or whether to fall back to text match. */
    public boolean hasBoundExecutionIndex() {
        return citedExecutionIndex >= 0;
    }
}
