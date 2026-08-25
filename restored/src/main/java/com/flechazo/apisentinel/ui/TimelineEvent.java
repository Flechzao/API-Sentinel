package com.flechazo.apisentinel.ui;

import java.time.Instant;

/**
 * A single event in the agent execution timeline.
 * Mirrors the data already flowing through AgentCallback and PipelineCallback
 * — no new data collection needed, just a structured representation.
 */
public record TimelineEvent(
        Instant timestamp,
        Type type,
        String summary,
        String detail,
        String cost,
        ColorHint colorHint
) {
    public enum Type {
        THINKING,
        TOOL_CALL,
        TOOL_RESULT,
        ITERATION,
        STAGE,
        VERDICT,
        ERROR
    }

    public enum ColorHint {
        NEUTRAL,    // gray — thinking, iteration markers
        FREE,       // blue — free tools (heuristic_scan, read_file, etc.)
        LLM,        // orange — tools that consume an LLM call (analyze_traffic, generate_payloads)
        ANOMALY,    // red — payload triggered anomaly, confirmed vuln
        WAF,        // yellow — WAF blocked
        SUCCESS,    // green — report submitted, analysis complete
        ERROR       // red — error
    }

    /** Create a thinking event. */
    public static TimelineEvent thinking(String thought) {
        String summary = thought.length() > 80 ? thought.substring(0, 77) + "..." : thought;
        return new TimelineEvent(Instant.now(), Type.THINKING, summary, thought, null, ColorHint.NEUTRAL);
    }

    /** Create a tool call event. */
    public static TimelineEvent toolCall(String toolName, String args, boolean isLlmCall) {
        return new TimelineEvent(
                Instant.now(), Type.TOOL_CALL,
                toolName + (args != null && !args.isEmpty() && !"{}".equals(args) ? " ..." : ""),
                args != null ? args : "",
                isLlmCall ? "1 LLM" : "免费",
                isLlmCall ? ColorHint.LLM : ColorHint.FREE);
    }

    /** Create a tool result event. */
    public static TimelineEvent toolResult(String toolName, String result, boolean anomalyDetected,
                                            boolean wafBlocked) {
        ColorHint hint = anomalyDetected ? ColorHint.ANOMALY
                : wafBlocked ? ColorHint.WAF
                : ColorHint.FREE;
        String summary = buildToolResultSummary(toolName, result);
        return new TimelineEvent(Instant.now(), Type.TOOL_RESULT, summary, result, null, hint);
    }

    /** Create an iteration marker. */
    public static TimelineEvent iteration(int iteration, int maxIterations) {
        return new TimelineEvent(
                Instant.now(), Type.ITERATION,
                "迭代 " + iteration + "/" + maxIterations + " 开始",
                null, null, ColorHint.NEUTRAL);
    }

    /** Create a stage event (Pipeline mode). */
    public static TimelineEvent stage(int stage, String description, boolean start) {
        return new TimelineEvent(
                Instant.now(), Type.STAGE,
                (start ? "▶ " : "✓ ") + "阶段 " + stage + "/6: " + description,
                null, null, ColorHint.NEUTRAL);
    }

    /** Create a verdict event. */
    public static TimelineEvent verdict(String overallRisk, int confirmed, int suspected, int demoted) {
        StringBuilder sb = new StringBuilder();
        sb.append(overallRisk).append(" — ");
        sb.append(confirmed).append(" 确认, ").append(suspected).append(" 疑似");
        if (demoted > 0) sb.append(", ").append(demoted).append(" 降级");
        return new TimelineEvent(
                Instant.now(), Type.VERDICT, sb.toString(), null, null,
                "HIGH".equals(overallRisk) ? ColorHint.ANOMALY : ColorHint.SUCCESS);
    }

    /** Create an error event. */
    public static TimelineEvent error(String error) {
        return new TimelineEvent(Instant.now(), Type.ERROR, error, error, null, ColorHint.ERROR);
    }

    private static String buildToolResultSummary(String toolName, String result) {
        if (result == null) return toolName + " → 完成";
        if (result.length() > 100) return toolName + " → " + result.substring(0, 97) + "...";
        return toolName + " → " + result;
    }
}