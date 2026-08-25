package com.flechazo.apisentinel.ai.pipeline;

/**
 * A finding the analysis suspects but couldn't confirm with hard evidence.
 *
 * {@code escalationPath} (Phase 4) is an optional, free-text hint at how a
 * weak suspected finding could be escalated into a real vuln when chained
 * with something else (e.g. "开放重定向 → 接 OAuth redirect_uri → 窃取授权码").
 * The LLM is encouraged (via FinalVerdictPrompt / AgentLoop's conditionally-
 * valid table) to fill it only for findings that have a known chain; findings
 * with no chain are left blank and fall under Phase 2's informational rules.
 */
public record SuspectedVuln(
    String type,
    String title,
    String reason,
    String verifyCommand,
    String confidence,
    String escalationPath,
    String payloadUsed
) {
    /** 6-arg compat: defaults payloadUsed to "" (no linked payload). */
    public SuspectedVuln(String type, String title, String reason, String verifyCommand, String confidence, String escalationPath) {
        this(type, title, reason, verifyCommand, confidence, escalationPath, "");
    }

    /** 5-arg compat: defaults escalationPath to "" (no chain) and payloadUsed to "". */
    public SuspectedVuln(String type, String title, String reason, String verifyCommand, String confidence) {
        this(type, title, reason, verifyCommand, confidence, "", "");
    }

    /** 4-arg compat: defaults confidence to MEDIUM, escalationPath and payloadUsed to "". */
    public SuspectedVuln(String type, String title, String reason, String verifyCommand) {
        this(type, title, reason, verifyCommand, "MEDIUM", "", "");
    }
}
