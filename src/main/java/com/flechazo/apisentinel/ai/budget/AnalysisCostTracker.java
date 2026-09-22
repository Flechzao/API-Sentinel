package com.flechazo.apisentinel.ai.budget;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Lightweight per-analysis token cost tracker. Records how many tokens each
 * LLM call consumed during a single endpoint analysis, and produces a
 * summary suitable for inclusion in the final report.
 *
 * <p>This is a monitoring-only component — it never blocks calls. It works
 * alongside {@link TokenBudgetManager} (which handles the global/daily gate)
 * to give per-endpoint granularity.
 *
 * <p>Usage:
 * <pre>
 *   AnalysisCostTracker tracker = new AnalysisCostTracker();
 *   tracker.recordCall("AgentLoop turn 3", 4500, 1200);
 *   tracker.recordCall("chain_hunter turn 1", 8000, 2000);
 *   String summary = tracker.summary();  // → "总消耗: 15.7K tokens (4 次 LLM 调用)"
 * </pre>
 */
public class AnalysisCostTracker {

    private long totalInput = 0;
    private long totalOutput = 0;
    private int callCount = 0;
    private final Map<String, long[]> perCall = new LinkedHashMap<>();

    public void recordCall(String label, int inputTokens, int outputTokens) {
        if (inputTokens <= 0 && outputTokens <= 0) return;
        totalInput += inputTokens;
        totalOutput += outputTokens;
        callCount++;
        perCall.put(label != null ? label : "call_" + callCount,
                new long[]{inputTokens, outputTokens});
    }

    public long getTotalTokens() {
        return totalInput + totalOutput;
    }

    public int getCallCount() {
        return callCount;
    }

    public long getTotalInput() {
        return totalInput;
    }

    public long getTotalOutput() {
        return totalOutput;
    }

    /**
     * Human-readable summary for report output.
     */
    public String summary() {
        if (callCount == 0) return "无 LLM 调用记录";
        long total = getTotalTokens();
        String totalStr = formatTokens(total);
        return String.format("总消耗: %s tokens (输入 %s + 输出 %s, %d 次 LLM 调用)",
                totalStr, formatTokens(totalInput), formatTokens(totalOutput), callCount);
    }

    /**
     * Detailed breakdown for verbose report output.
     */
    public String detail() {
        if (callCount == 0) return "";
        StringBuilder sb = new StringBuilder();
        sb.append("## Token 消耗明细\n\n");
        sb.append("| 调用 | 输入 | 输出 | 合计 |\n");
        sb.append("|------|------|------|------|\n");
        for (Map.Entry<String, long[]> e : perCall.entrySet()) {
            long in = e.getValue()[0];
            long out = e.getValue()[1];
            sb.append("| ").append(e.getKey())
              .append(" | ").append(formatTokens(in))
              .append(" | ").append(formatTokens(out))
              .append(" | ").append(formatTokens(in + out))
              .append(" |\n");
        }
        sb.append("| **合计** | **").append(formatTokens(totalInput))
          .append("** | **").append(formatTokens(totalOutput))
          .append("** | **").append(formatTokens(getTotalTokens()))
          .append("** |\n");
        return sb.toString();
    }

    private static String formatTokens(long n) {
        if (n >= 1_000_000) return String.format("%.1fM", n / 1_000_000.0);
        if (n >= 1_000) return String.format("%.1fK", n / 1_000.0);
        return String.valueOf(n);
    }
}
