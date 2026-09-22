package com.flechazo.apisentinel.ai.agent;

import com.flechazo.apisentinel.logging.LeveledLogger;

import java.util.List;
import java.util.stream.Collectors;

/**
 * Smart Cascade Error Compressor — inspired by IEEE ICNDSA 2026.
 *
 * <p>When a batch of tool calls (e.g., 5 send_request payloads) all fail,
 * instead of injecting ~5000 tokens of raw error results into the context,
 * compress them into a ~200 token diagnostic summary with an actionable pivot.
 *
 * <p>Key finding from IEEE ICNDSA 2026: diagnostic compression achieves
 * <strong>59.76% recovery rate</strong> vs 21.34% for naive full-pass transfer
 * (passing all raw errors to the next model/attempt).
 *
 * <p>Integration in AgentLoop:
 * <pre>
 * // After a batch of send_request calls:
 * if (allFailed && "send_request".equals(toolName)) {
 *     var diagnosis = errorCompressor.diagnoseBatch(toolResults, parameter, codeContext);
 *     // Replace raw results with compressed diagnosis
 *     messages.add(ChatMessage.toolResult(tc.id(), diagnosis.compressedText()));
 *     // Also generate a reflection
 *     reflectionMemory.addReflectionDirect(diagnosis.category(), ...);
 * }
 * </pre>
 */
public class ErrorCompressor {

    /** Failure patterns detected from batch results. */
    public enum FailurePattern {
        ALL_NORMAL("all_normal", "全部返回正常响应"),
        ALL_WAF_BLOCKED("all_waf", "全部被 WAF 拦截"),
        ALL_AUTH_FAILED("auth_failed", "全部认证失败"),
        ALL_TIMEOUT("timeout", "全部超时"),
        MIXED_ERRORS("mixed", "混合错误"),
        RATE_LIMITED("rate_limited", "被限流");

        private final String tag;
        private final String displayName;
        FailurePattern(String tag, String displayName) {
            this.tag = tag;
            this.displayName = displayName;
        }
        public String tag() { return tag; }
        public String displayName() { return displayName; }
    }

    /**
     * Compressed diagnosis from a failed batch.
     *
     * @param pattern          detected failure pattern
     * @param totalResults     number of results in the batch
     * @param parameterAnalysis brief analysis of the parameter
     * @param suggestedPivot   specific corrective action
     * @param originalTokens   estimated original token count
     * @param compressedTokens estimated compressed token count
     */
    public record Diagnosis(
            FailurePattern pattern,
            int totalResults,
            String parameterAnalysis,
            String suggestedPivot,
            int originalTokens,
            int compressedTokens
    ) {
        /**
         * Format the diagnosis as text for injection into messages.
         */
        public String compressedText() {
            return String.format(
                    "【批次诊断】%d 个请求 → %s\n" +
                    "分析: %s\n" +
                    "建议: %s\n" +
                    "（原始 ~%d tokens 已压缩为 ~%d tokens）",
                    totalResults, pattern.displayName(),
                    parameterAnalysis, suggestedPivot,
                    originalTokens, compressedTokens);
        }

        /**
         * Reflection category tag for EpisodicReflectionMemory.
         */
        public String reflectionCategory() {
            return switch (pattern) {
                case ALL_WAF_BLOCKED -> "waf_blocked";
                case ALL_AUTH_FAILED -> "auth_failed";
                case ALL_TIMEOUT -> "timeout";
                case RATE_LIMITED -> "rate_limited";
                case ALL_NORMAL -> "param_not_injectable";
                case MIXED_ERRORS -> "mixed_errors";
            };
        }
    }

    private final LeveledLogger logger;

    public ErrorCompressor(LeveledLogger logger) {
        this.logger = logger;
    }

    /**
     * Diagnose a batch of failed tool results.
     *
     * @param results     list of raw tool result strings
     * @param parameter   the parameter being tested (for context)
     * @param codeContext brief code context (e.g., "Integer type, no sanitization")
     * @return compressed diagnosis
     */
    public Diagnosis diagnoseBatch(List<String> results, String parameter, String codeContext) {
        if (results == null || results.isEmpty()) {
            return new Diagnosis(FailurePattern.MIXED_ERRORS, 0,
                    "无结果", "检查工具调用参数", 0, 50);
        }

        // P0-5: classify each result through the same structured-first /
        // substring-fallback path used by classifySingleResult. The
        // pre-P0-5 loop duplicated the substring logic inline and checked
        // patterns in the wrong order — a response body containing both
        // "200" (legitimate) and "blocked" (HTML prose) could tip either
        // way depending on which branch fired first.
        int normalCount = 0, wafCount = 0, authCount = 0,
                timeoutCount = 0, rateLimitCount = 0, mixedCount = 0;

        for (String result : results) {
            if (result == null) continue;
            switch (classifySingleResult(result)) {
                case ALL_WAF_BLOCKED -> wafCount++;
                case ALL_AUTH_FAILED -> authCount++;
                case ALL_TIMEOUT -> timeoutCount++;
                case RATE_LIMITED -> rateLimitCount++;
                case ALL_NORMAL -> normalCount++;
                case MIXED_ERRORS -> mixedCount++;
            }
        }

        int total = results.size();
        FailurePattern pattern;

        if (wafCount >= total * 0.8) {
            pattern = FailurePattern.ALL_WAF_BLOCKED;
        } else if (authCount >= total * 0.8) {
            pattern = FailurePattern.ALL_AUTH_FAILED;
        } else if (timeoutCount >= total * 0.8) {
            pattern = FailurePattern.ALL_TIMEOUT;
        } else if (rateLimitCount >= total * 0.8) {
            pattern = FailurePattern.RATE_LIMITED;
        } else if (normalCount >= total * 0.8) {
            pattern = FailurePattern.ALL_NORMAL;
        } else {
            pattern = FailurePattern.MIXED_ERRORS;
        }

        String paramAnalysis = buildParameterAnalysis(pattern, parameter, codeContext);
        String pivot = buildPivotSuggestion(pattern, parameter);

        // P0-5: measure what we actually emit, not a hardcoded literal. The
        // pre-P0-5 "compressedTokens = 200" was fiction — the compressed
        // text was routinely ~290 tokens (a 70× inflation on the 4-token
        // synthetic probe AgentLoop fed in). Estimating from the rendered
        // diagnosis length keeps the number honest and makes the audit
        // trail readable: the field now means what the label says.
        Diagnosis draft = new Diagnosis(pattern, total, paramAnalysis, pivot, 0, 0);
        int compressedTokens = estimateTokens(draft.compressedText());
        int originalTokens = results.stream()
                .mapToInt(r -> r != null ? estimateTokens(r) : 0)
                .sum();

        Diagnosis diagnosis = new Diagnosis(pattern, total,
                paramAnalysis, pivot, originalTokens, compressedTokens);

        logger.debug("[ErrorCompressor] %s: %d/%d (%s), 压缩 %d→%d tokens",
                pattern.displayName(), getCount(pattern, normalCount, wafCount,
                        authCount, timeoutCount, rateLimitCount),
                total, parameter, originalTokens, compressedTokens);

        return diagnosis;
    }

    /** Token-count estimate shared by {@link #diagnoseBatch} and the
     *  post-hoc measurement of the compressed diagnosis. Matches the
     *  existing heuristic used elsewhere in the agent (≈ 1 token per
     *  4 bytes of UTF-8 text) so the field is comparable across logs. */
    private static int estimateTokens(String text) {
        if (text == null || text.isEmpty()) return 0;
        return Math.max(1, text.length() / 4);
    }

    /**
     * Classify a single tool result's failure pattern.
     *
     * <p>P0-5 hardening: the pre-P0-5 classifier ran substring matches
     * over the raw result text and checked them in the wrong order —
     * {@code "200"} in a response body could coexist with {@code "blocked"}
     * in HTML prose, and whichever branch came first won. Worse, it
     * happily misread a synthetic {@code "all responses normal"} probe as
     * WAF-blocked because "blocked" appeared in the English phrasing.
     *
     * <p>New behaviour: when the result is valid JSON carrying the
     * structured fields {@link SendRequestTool} emits ({@code status_code},
     * {@code waf_detected}, {@code waf_score}), classify from those —
     * they're unambiguous. Substring matching is retained as a fallback
     * for plain-text results from other tools, with the priority order
     * flipped so WAF signals (strongest, cheapest to detect) fire first
     * and "normal" is the <i>last</i> resort rather than the first.
     */
    public FailurePattern classifySingleResult(String result) {
        if (result == null || result.isBlank()) return FailurePattern.MIXED_ERRORS;

        // Fast path: structured JSON from SendRequestTool / verify_* tools.
        FailurePattern structured = classifyFromStructured(result);
        if (structured != null) return structured;

        // Fallback: substring matching against plain-text results. The
        // order matters — WAF / auth / timeout / rate-limit are all
        // specific failure modes; "normal" is the default when nothing
        // else matched.
        String lower = result.toLowerCase(java.util.Locale.ROOT);
        if (lower.contains("waf_detected") || lower.contains("waf")
                || lower.contains("blocked") || lower.contains("拦截")) {
            return FailurePattern.ALL_WAF_BLOCKED;
        }
        if (lower.contains("401") || lower.contains("403")
                || lower.contains("unauthorized") || lower.contains("认证")) {
            return FailurePattern.ALL_AUTH_FAILED;
        }
        if (lower.contains("timeout") || lower.contains("超时")) {
            return FailurePattern.ALL_TIMEOUT;
        }
        if (lower.contains("429") || lower.contains("rate_limit")
                || lower.contains("限流")) {
            return FailurePattern.RATE_LIMITED;
        }
        if (lower.contains("error")) {
            return FailurePattern.MIXED_ERRORS;
        }
        return FailurePattern.ALL_NORMAL;
    }

    /** Try to classify from structured JSON fields emitted by
     *  {@link com.flechazo.apisentinel.ai.agent.tool.SendRequestTool}.
     *  Returns null when the input isn't a JSON object or doesn't carry
     *  any of the fields we recognise — caller falls back to substring
     *  matching. Never throws: a malformed result just means "not JSON". */
    private FailurePattern classifyFromStructured(String result) {
        com.google.gson.JsonElement parsed;
        try {
            parsed = com.google.gson.JsonParser.parseString(result);
        } catch (com.google.gson.JsonSyntaxException e) {
            return null;
        }
        if (parsed == null || !parsed.isJsonObject()) return null;
        com.google.gson.JsonObject obj = parsed.getAsJsonObject();

        // WAF signal — strongest and unambiguous. waf_score ≥ 60 is the
        // WafDetector.WAF_BLOCKED threshold (see PayloadResult.WAF_BLOCKED);
        // 30-59 is the "needs review" band (treated as WAF-blocked for
        // failure classification — the probe didn't reach the backend).
        if (obj.has("waf_detected") && obj.get("waf_detected").getAsBoolean()) {
            return FailurePattern.ALL_WAF_BLOCKED;
        }
        if (obj.has("waf_score") && obj.get("waf_score").getAsInt() >= 30) {
            return FailurePattern.ALL_WAF_BLOCKED;
        }

        // Status code — only when present.
        if (obj.has("status_code") && obj.get("status_code").isJsonPrimitive()) {
            int status = obj.get("status_code").getAsInt();
            if (status == 401 || status == 403) return FailurePattern.ALL_AUTH_FAILED;
            if (status == 429) return FailurePattern.RATE_LIMITED;
            if (status == 408 || status == 504) return FailurePattern.ALL_TIMEOUT;
            if (status >= 500) return FailurePattern.MIXED_ERRORS;
            if (status >= 200 && status < 300) {
                // 2xx on the wire, but the tool may still have flagged an
                // anomaly (response-content-based detection). Respect the
                // anomaly flag over the raw status code.
                if (obj.has("anomaly") && obj.get("anomaly").getAsBoolean()) {
                    return FailurePattern.MIXED_ERRORS;
                }
                return FailurePattern.ALL_NORMAL;
            }
            // 4xx other than the auth/rate-limit pair above — mixed.
            return FailurePattern.MIXED_ERRORS;
        }

        // Anomaly-only payload (some verify_* tools emit just that).
        if (obj.has("anomaly")) {
            return obj.get("anomaly").getAsBoolean()
                    ? FailurePattern.MIXED_ERRORS
                    : FailurePattern.ALL_NORMAL;
        }
        return null;
    }

    // ── Internal ──

    private String buildParameterAnalysis(FailurePattern pattern, String param, String codeContext) {
        return switch (pattern) {
            case ALL_NORMAL -> String.format(
                    "参数 '%s' 的所有 payload 均返回正常响应。" +
                    "可能原因: 1) 参数不可注入(已被转义/参数化查询) " +
                    "2) payload 类型不匹配(数字参数用了字符串payload) " +
                    "3) 该参数确实不存在注入点", param);
            case ALL_WAF_BLOCKED -> String.format(
                    "参数 '%s' 的所有 payload 被 WAF 拦截。" +
                    "说明 WAF 正在监控此参数，但不代表不存在漏洞——" +
                    "需要绕过 WAF 或使用不依赖响应内容差异的检测技术", param);
            case ALL_AUTH_FAILED -> String.format(
                    "参数 '%s' 的测试全部因认证失败被拒绝。" +
                    "当前 session token 可能已过期或权限不足", param);
            case ALL_TIMEOUT -> String.format(
                    "参数 '%s' 的测试全部超时。" +
                    "可能原因: payload 触发了长时间处理、目标服务过载、网络连接问题", param);
            case RATE_LIMITED -> String.format(
                    "参数 '%s' 的测试被限流。需要降低请求频率或等待冷却期", param);
            case MIXED_ERRORS -> String.format(
                    "参数 '%s' 的测试结果不一致（部分正常、部分异常）。" +
                    "需要逐个分析每个结果的响应差异", param);
        };
    }

    private String buildPivotSuggestion(FailurePattern pattern, String param) {
        return switch (pattern) {
            case ALL_NORMAL -> String.format(
                    "1) 检查参数 '%s' 的数据类型是否匹配（数字参数用数字 payload）" +
                    "2) 尝试 verify_boolean_blind（不依赖响应内容差异）" +
                    "3) 尝试 verify_timing_blind（利用响应时间差异）" +
                    "4) 如果以上都失败，转向其他漏洞类别或参数", param);
            case ALL_WAF_BLOCKED -> String.format(
                    "1) 调用 waf_bypass_retry 尝试编码绕过（大小写/注释/Unicode）" +
                    "2) 使用语义等效但无关键字的 payload（如用 CONCAT 替代 UNION SELECT）" +
                    "3) 尝试 verify_timing_blind（时间盲注通常不受 WAF 影响）" +
                    "4) 如果所有绕过失败，在报告中标注 WAF 防护有效");
            case ALL_AUTH_FAILED -> String.format(
                    "1) 调用 search_traffic 获取有效的 session token" +
                    "2) 调用 test_auth_bypass 检查是否有绕过认证的方式" +
                    "3) 检查是否需要不同的认证角色（如 admin token）");
            case ALL_TIMEOUT -> String.format(
                    "1) 缩短 payload 长度，减少服务器处理时间" +
                    "2) 降低请求频率（间隔发送）" +
                    "3) 检查目标服务是否正常运行");
            case RATE_LIMITED -> String.format(
                    "1) 等待 30 秒后重试" +
                    "2) 减少单次批量大小（从 5 个减到 2 个）" +
                    "3) 先测试其他参数，稍后回来重试");
            case MIXED_ERRORS -> String.format(
                    "1) 逐个分析每个响应的具体差异" +
                    "2) 聚焦返回异常的那个结果，深入验证" +
                    "3) 如果只有一个异常响应，可能是一次性波动而非漏洞");
        };
    }

    private int getCount(FailurePattern pattern, int normal, int waf,
                          int auth, int timeout, int rateLimit) {
        return switch (pattern) {
            case ALL_NORMAL -> normal;
            case ALL_WAF_BLOCKED -> waf;
            case ALL_AUTH_FAILED -> auth;
            case ALL_TIMEOUT -> timeout;
            case RATE_LIMITED -> rateLimit;
            case MIXED_ERRORS -> normal + waf + auth + timeout + rateLimit;
        };
    }
}
