package com.flechazo.apisentinel.ai.pipeline;

import com.flechazo.apisentinel.model.AnalysisRecord;
import com.flechazo.apisentinel.model.ApiEntry;

/**
 * Shared utility for building a "prior analysis context" section — the
 * reuse-window soft fold. Both {@link AnalysisPipeline} and
 * {@code AgentLoop} call this to inject the prior verdict as a "known
 * starting point" so the model confirms/corrects rather than re-derives.
 *
 * <p>Extracted to eliminate the duplication between Pipeline and Agent
 * (the two implementations were ~35 identical lines each).
 *
 * @see <a href="docs/plan/reuse-window-agent-migration.md">reuse-window-agent-migration.md</a>
 */
public final class PriorAnalysisContextBuilder {

    private PriorAnalysisContextBuilder() {}

    /**
     * Build a summary of the prior verdict for injection into the prompt.
     *
     * @param entry              the API entry to look up the prior record for
     * @param reuseWindowMinutes time window in minutes; {@code <=0} disables
     * @return non-empty summary text, or empty string when reuse is disabled,
     *         no prior record exists, the record is outside the time window,
     *         or the record has no verdict
     */
    public static String build(ApiEntry entry, int reuseWindowMinutes) {
        if (reuseWindowMinutes <= 0) return "";
        try {
            AnalysisRecord latest = entry.getLatestAnalysisRecord();
            if (latest == null) return "";
            long ageMs = System.currentTimeMillis() - latest.timestamp();
            if (ageMs < 0 || ageMs > reuseWindowMinutes * 60_000L) return "";
            if (!latest.hasPipelineResult() || latest.pipelineResult().verdict() == null) return "";

            var verdict = latest.pipelineResult().verdict();
            StringBuilder sb = new StringBuilder();
            sb.append("## 上次分析结论（").append(reuseWindowMinutes)
              .append(" 分钟内，作为已知起点，请确认/修正而非重新推导）\n");
            sb.append("总体风险: ").append(verdict.overallRisk()).append("\n");
            if (verdict.confirmedVulns() != null && !verdict.confirmedVulns().isEmpty()) {
                sb.append("已确认漏洞:\n");
                for (var cv : verdict.confirmedVulns()) {
                    sb.append("- [").append(cv.type()).append("] ").append(cv.title()).append("\n");
                }
            }
            if (verdict.suspectedVulns() != null && !verdict.suspectedVulns().isEmpty()) {
                sb.append("疑似漏洞:\n");
                for (var sv : verdict.suspectedVulns()) {
                    sb.append("- [").append(sv.type()).append("] ").append(sv.title()).append("\n");
                }
            }
            if (verdict.summary() != null && !verdict.summary().isBlank()) {
                String s = verdict.summary();
                sb.append("摘要: ").append(s.length() > 800 ? s.substring(0, 800) + "..." : s).append("\n");
            }
            return sb.toString();
        } catch (Exception e) {
            return "";
        }
    }
}
