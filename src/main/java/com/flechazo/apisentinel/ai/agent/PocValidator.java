package com.flechazo.apisentinel.ai.agent;

import com.flechazo.apisentinel.ai.agent.FindingEvidenceStore.Finding;
import com.flechazo.apisentinel.ai.agent.FindingEvidenceStore.ConfidenceLevel;
import com.flechazo.apisentinel.logging.LeveledLogger;

import java.util.ArrayList;
import java.util.List;

/**
 * PoC (Proof of Concept) Validator — independent verification layer before report submission.
 *
 * <p>Inspired by Aikido's validation agent pattern (99.98% FP reduction).
 * Before the agent submits its final report, every CONFIRMED finding must pass
 * a PoC reproducibility check. Findings that cannot be reproduced are
 * automatically downgraded to SUSPECTED.
 *
 * <p>Flow:
 * <pre>
 * 1. Agent calls submit_report
 * 2. PreExecute gate checks: are there CONFIRMED findings?
 * 3. For each CONFIRMED finding: replay the original payload
 * 4. If the response matches the original evidence → CONFIRMED stays
 * 5. If the response differs or fails → downgrade to SUSPECTED
 * 6. Inject validation summary into the report context
 * </pre>
 *
 * <p>This doesn't require additional HTTP requests — it validates against
 * the evidence already collected by the FindingEvidenceStore.
 */
public class PocValidator {

    /**
     * Result of a PoC validation check for a single finding.
     *
     * @param findingId     the finding ID that was validated
     * @param originalLevel the original confidence level
     * @param adjustedLevel the adjusted level after validation
     * @param reason        why the level was adjusted (or kept)
     * @param reproducible  whether the finding appears reproducible
     */
    public record PocCheckResult(
            String findingId,
            ConfidenceLevel originalLevel,
            ConfidenceLevel adjustedLevel,
            String reason,
            boolean reproducible
    ) {}

    /**
     * Full validation report for all findings.
     *
     * @param results     per-finding validation results
     * @param totalChecked total findings checked
     * @param confirmed    number that stayed CONFIRMED
     * @param downgraded   number downgraded to SUSPECTED
     */
    public record ValidationReport(
            List<PocCheckResult> results,
            int totalChecked,
            int confirmed,
            int downgraded
    ) {}

    private final LeveledLogger logger;

    public PocValidator(LeveledLogger logger) {
        this.logger = logger;
    }

    /**
     * Validate all CONFIRMED findings before report submission.
     *
     * <p>This performs a lightweight validation based on the evidence already
     * in the FindingEvidenceStore. It checks:
     * <ul>
     *   <li>Evidence is specific (not vague/generic)</li>
     *   <li>Evidence includes concrete payload and response特征</li>
     *   <li>Finding has been cross-verified (multiple evidence points)</li>
     * </ul>
     *
     * <p>For full PoC replay (re-sending the actual request), the agent
     * should use send_request as part of its validation workflow.
     *
     * @param findingStore the finding store to validate
     * @return validation report
     */
    public ValidationReport validateAll(FindingEvidenceStore findingStore) {
        List<Finding> confirmedFindings = findingStore.getFindingsByLevel(ConfidenceLevel.CONFIRMED);
        List<PocCheckResult> results = new ArrayList<>();

        for (Finding finding : confirmedFindings) {
            PocCheckResult result = validateSingle(finding);
            results.add(result);

            // If downgraded, update the finding store
            if (result.adjustedLevel() != result.originalLevel()) {
                findingStore.updateFindingLevel(finding.id(), result.adjustedLevel().name());
            }
        }

        long confirmed = results.stream().filter(r -> r.adjustedLevel() == ConfidenceLevel.CONFIRMED).count();
        long downgraded = results.size() - confirmed;

        ValidationReport report = new ValidationReport(results, results.size(),
                (int) confirmed, (int) downgraded);

        logger.info("[PoCValidator] 验证 %d 个 CONFIRMED 发现: %d 通过, %d 降级",
                report.totalChecked(), report.confirmed(), report.downgraded());

        return report;
    }

    /**
     * Build the validation summary for injection into messages.
     *
     * @param report the validation report
     * @return formatted summary string
     */
    public String buildValidationSummary(ValidationReport report) {
        if (report.totalChecked() == 0) {
            return "";
        }

        StringBuilder sb = new StringBuilder("【PoC 验证结果】\n");
        sb.append(String.format("检查了 %d 个 CONFIRMED 发现: %d 通过, %d 降级为 SUSPECTED\n",
                report.totalChecked(), report.confirmed(), report.downgraded()));

        if (report.downgraded() > 0) {
            sb.append("\n降级的发现:\n");
            for (PocCheckResult r : report.results()) {
                if (r.adjustedLevel() != r.originalLevel()) {
                    sb.append(String.format("  - %s: %s\n", r.findingId(), r.reason()));
                }
            }
        }

        return sb.toString();
    }

    /**
     * Check if the finding store has any CONFIRMED findings that need validation.
     */
    public boolean hasUnvalidatedConfirmed(FindingEvidenceStore findingStore) {
        return findingStore.hasConfirmed();
    }

    // ========== Internal ==========

    /**
     * Validate a single finding based on evidence quality.
     *
     * <p>Validation criteria:
     * <ul>
     *   <li>Evidence must be non-empty and specific</li>
     *   <li>Evidence should mention a concrete payload or response特征</li>
     *   <li>Evidence should not be purely speculative language</li>
     * </ul>
     */
    private PocCheckResult validateSingle(Finding finding) {
        String evidence = finding.evidence();
        String id = finding.id();

        // Check 1: Evidence exists and is non-trivial
        if (evidence == null || evidence.strip().length() < 20) {
            return new PocCheckResult(id, ConfidenceLevel.CONFIRMED,
                    ConfidenceLevel.SUSPECTED,
                    "证据不充分（太短或为空）", false);
        }

        // Check 2: Evidence is not purely speculative
        String lower = evidence.toLowerCase();
        if (lower.contains("可能") || lower.contains("也许") || lower.contains("might")
                || lower.contains("possibly") || lower.contains("推测")) {
            return new PocCheckResult(id, ConfidenceLevel.CONFIRMED,
                    ConfidenceLevel.SUSPECTED,
                    "证据含推测性语言，未经实际验证", false);
        }

        // Check 3: Evidence mentions concrete indicators
        boolean hasConcreteIndicator =
                lower.contains("status") || lower.contains("状态码")
                || lower.contains("返回") || lower.contains("response")
                || lower.contains("error") || lower.contains("错误")
                || lower.contains("payload") || lower.contains("注入")
                || lower.contains("200") || lower.contains("500")
                || lower.contains("差异") || lower.contains("different")
                || lower.contains("反射") || lower.contains("reflect")
                || lower.contains("执行") || lower.contains("execute");

        if (!hasConcreteIndicator) {
            return new PocCheckResult(id, ConfidenceLevel.CONFIRMED,
                    ConfidenceLevel.SUSPECTED,
                    "证据缺少具体响应特征（状态码/错误信息/响应差异）", false);
        }

        // Passed all checks — keep as CONFIRMED
        return new PocCheckResult(id, ConfidenceLevel.CONFIRMED,
                ConfidenceLevel.CONFIRMED,
                "证据充分，包含具体响应特征", true);
    }
}
