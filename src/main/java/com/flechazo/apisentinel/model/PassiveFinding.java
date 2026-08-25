package com.flechazo.apisentinel.model;

import java.util.UUID;

/**
 * One local passive-detection finding (zero-AI-cost layer: sensitive-info
 * rules / heuristic regexes / unauthorized-access probe). Kept strictly
 * separate from AI output (AnalysisRecord/PipelineResult) — the "被动" table
 * column renders these; the "发现" column stays AI-only.
 *
 * De-duplication key is (source, title) via
 * {@link ApiEntry#addPassiveFindingIfAbsent(PassiveFinding)} — replacing the
 * old note.contains(marker) string guards.
 */
public record PassiveFinding(
        String id,            // 8-char random, same style as ApiEntry ids
        Source source,        // which detector produced it
        String risk,          // HIGH / MEDIUM / LOW / INFO
        String category,      // e.g. "CORS 配置错误", "敏感信息", "越权"
        String title,         // rule name / heuristic title / fixed probe name
        String evidence,      // observed facts (no static boilerplate)
        String remediation,   // fix advice (HeuristicFinding native; may be "")
        long detectedAt       // System.currentTimeMillis()
) {
    public enum Source { SENSITIVE_INFO, HEURISTIC, UNAUTHORIZED }

    /** 8-char id in the project's existing style (see ApiEntry constructor). */
    public static String newId() {
        return UUID.randomUUID().toString().substring(0, 8);
    }
}
