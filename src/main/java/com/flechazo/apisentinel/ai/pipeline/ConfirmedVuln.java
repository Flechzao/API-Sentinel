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
 */
public record ConfirmedVuln(
    String type,
    String title,
    String evidence,
    String payloadUsed,
    String response,
    String verifyCommand,
    String identityProof,
    String cvss
) {
    /** Backward-compatible constructor (no identity proof / CVSS). */
    public ConfirmedVuln(String type, String title, String evidence,
                         String payloadUsed, String response, String verifyCommand) {
        this(type, title, evidence, payloadUsed, response, verifyCommand, "", "");
    }
}
