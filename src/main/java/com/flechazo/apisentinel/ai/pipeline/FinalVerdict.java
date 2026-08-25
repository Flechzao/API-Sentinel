package com.flechazo.apisentinel.ai.pipeline;

import java.util.List;

/**
 * The comprehensive final verdict produced by Stage 6 of the pipeline.
 *
 * @param rejectionReasons structured audit trail of everything the
 *                         VerdictValidator demoted / downgraded / flagged:
 *                         hallucinated confirms (payload never sent), WAF-blocked
 *                         confirms, identity_not_proven demotions, HIGH-without-
 *                         confirmed risk downgrades, and soft conflicts with the
 *                         programmatic auth test. Rendered in the full report's
 *                         验证门禁 section.
 */
public record FinalVerdict(
    String overallRisk,
    List<ConfirmedVuln> confirmedVulns,
    List<SuspectedVuln> suspectedVulns,
    String summary,
    String recommendations,
    int totalTokensUsed,
    List<String> rejectionReasons
) {
    /** Backward-compatible constructor (no rejection reasons). */
    public FinalVerdict(String overallRisk, List<ConfirmedVuln> confirmedVulns,
                        List<SuspectedVuln> suspectedVulns, String summary,
                        String recommendations, int totalTokensUsed) {
        this(overallRisk, confirmedVulns, suspectedVulns, summary, recommendations,
                totalTokensUsed, List.of());
    }
}
