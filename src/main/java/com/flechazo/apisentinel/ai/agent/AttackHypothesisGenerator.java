package com.flechazo.apisentinel.ai.agent;

import com.flechazo.apisentinel.ai.agent.AnalysisStateTracker.VulnCategory;
import com.flechazo.apisentinel.ai.provider.LlmProvider;
import com.flechazo.apisentinel.ai.provider.LlmRequest;
import com.flechazo.apisentinel.logging.LeveledLogger;
import com.flechazo.apisentinel.model.ApiEntry;

import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

/**
 * Attack Hypothesis Generator — Graph-of-Thought (GoT) style attack exploration.
 *
 * <p>Based on ETH Zurich's GoT paper (Graph of Thoughts): 62% quality improvement
 * over Tree-of-Thought, 31% cost reduction. The key GoT advantage is that
 * different reasoning branches can <em>merge</em> — combining good ideas from
 * parallel paths into a unified attack chain.
 *
 * <p>Instead of testing vulnerabilities blindly one-by-one, this generator:
 * <ol>
 *   <li><b>BRANCH</b>: Generate 3-5 parallel attack hypotheses after recon</li>
 *   <li><b>SCORE</b>: Update hypothesis scores based on test results</li>
 *   <li><b>PRUNE</b>: Abandon low-scoring hypotheses</li>
 *   <li><b>MERGE</b>: Combine hypotheses that share a root cause into attack chains</li>
 *   <li><b>REFINE</b>: Focus resources on the most promising hypothesis</li>
 * </ol>
 *
 * <p>The hypothesis board is injected into messages at reflection checkpoints,
 * giving the agent a clear visual overview of what's been tried, what worked,
 * and what to focus on next.
 *
 * <p>Integration: opt-in via fast model configuration (same as PlanThenExecute).
 */
public class AttackHypothesisGenerator {

    /** Hypothesis status lifecycle. */
    public enum HypothesisStatus {
        PENDING("⏳"),
        TESTING("🔄"),
        CONFIRMED("✅"),
        SUSPECTED("❓"),
        PRUNED("✗"),
        MERGED("🔗");

        private final String icon;
        HypothesisStatus(String icon) { this.icon = icon; }
        public String icon() { return icon; }
    }

    /**
     * A single attack hypothesis.
     *
     * @param id         unique ID ("H1", "H2"...)
     * @param vulnType   vulnerability category
     * @param parameter  target parameter or endpoint
     * @param rationale  why this hypothesis exists
     * @param score      feasibility score (0.0-1.0, higher = more likely)
     * @param status     lifecycle status
     * @param evidence   accumulated evidence strings
     */
    public record Hypothesis(
            String id,
            VulnCategory vulnType,
            String parameter,
            String rationale,
            double score,
            HypothesisStatus status,
            List<String> evidence
    ) {
        /** Create a copy with updated fields. */
        Hypothesis withScore(double newScore) {
            return new Hypothesis(id, vulnType, parameter, rationale,
                    Math.max(0.0, Math.min(1.0, newScore)), status, evidence);
        }

        Hypothesis withStatus(HypothesisStatus newStatus) {
            return new Hypothesis(id, vulnType, parameter, rationale, score, newStatus, evidence);
        }

        Hypothesis withAddedEvidence(String newEvidence) {
            List<String> updated = new ArrayList<>(evidence);
            updated.add(newEvidence);
            return new Hypothesis(id, vulnType, parameter, rationale, score, status, updated);
        }
    }

    private final Map<String, Hypothesis> hypotheses = new LinkedHashMap<>();
    private final LeveledLogger logger;
    private int nextId = 1;
    private boolean generated = false;
    /** Fast model name for cheap hypothesis-generation LLM calls. */
    private String fastModelName;

    /** Score threshold below which a hypothesis is pruned. */
    private static final double PRUNE_THRESHOLD = 0.15;
    /** Maximum hypotheses to generate per branch. */
    private static final int MAX_BRANCHES = 5;

    public AttackHypothesisGenerator(LeveledLogger logger) {
        this.logger = logger;
    }

    /** Set the fast model name for cheap hypothesis-generation LLM calls. */
    public void setFastModelName(String name) {
        this.fastModelName = name;
    }

    // ========== BRANCH: Generate Hypotheses ==========

    /**
     * Generate attack hypotheses after reconnaissance is complete.
     *
     * <p>Uses the analysis profile's priority categories to seed hypotheses,
     * and the recon results to identify specific parameters and attack surfaces.
     *
     * @param entry       the API entry being analyzed
     * @param scanResult  heuristic_scan result (may contain parameter info)
     * @param profile     the analysis profile (priority categories)
     * @param provider    LLM provider for hypothesis generation
     * @return list of generated hypotheses, or empty list on failure
     */
    public List<Hypothesis> branch(ApiEntry entry, String scanResult,
                                    AnalysisProfile.ProfileResult profile,
                                    LlmProvider provider) {
        if (generated) return List.of();

        // Without an LLM provider, use fallback (profile-based hypotheses)
        if (provider == null) {
            return generateFallbackHypotheses(profile);
        }

        String method = entry.getHttpMethod() != null ? entry.getHttpMethod() : "GET";
        String path = entry.getApiPath() != null ? entry.getApiPath() : "unknown";

        // Build priority categories string for the prompt
        String priorityCats = profile.priorityCategories().stream()
                .map(VulnCategory::displayName)
                .collect(Collectors.joining(", "));

        String prompt = String.format("""
                基于以下侦察结果，为 API 安全测试生成 3-5 个攻击假设。

                ## 目标 API
                %s %s

                ## 重点漏洞类别
                %s

                ## 侦察结果
                %s

                请输出严格 JSON（不要 markdown）：
                {
                  "hypotheses": [
                    {
                      "vuln_type": "漏洞类型（英文枚举，如 SQL_INJECTION, IDOR, XSS, SSRF, AUTH_BYPASS, COMMAND_INJECTION, PATH_TRAVERSAL, XXE, SSTI, BUSINESS_LOGIC 等）",
                      "parameter": "目标参数名或端点",
                      "rationale": "为什么这个参数可能存在该漏洞（一句话）",
                      "score": 0.7
                    }
                  ]
                }

                规则：
                - 按可能性从高到低排列
                - score 范围 0.0-1.0，基于侦察证据给出合理评分
                - 最多 %d 个假设
                - 每个假设必须对应不同的漏洞类型
                - vuln_type 使用大写英文枚举值
                """,
                method, path,
                priorityCats,
                truncate(scanResult, 1500),
                MAX_BRANCHES);

        try {
            var request = new LlmRequest(
                    "你是 API 安全攻击假设生成专家。输出严格 JSON。",
                    prompt, 1536);
            // Use fast model if configured (same provider, cheaper model)
            if (fastModelName != null && !fastModelName.isBlank()) {
                request = request.withModelOverride(fastModelName);
            }
            String response = provider.complete(request)
                    .get(60, TimeUnit.SECONDS)
                    .content();

            List<Hypothesis> result = parseHypotheses(response);
            generated = true;

            logger.debug("[HypothesisGen] 生成 %d 个攻击假设", result.size());
            return result;
        } catch (Exception e) {
            logger.warn("[HypothesisGen] 假设生成失败: %s", e.getMessage());
            // Fallback: generate basic hypotheses from profile categories
            return generateFallbackHypotheses(profile);
        }
    }

    // ========== SCORE: Update Based on Test Results ==========

    /**
     * Update a hypothesis score based on test results.
     *
     * <p>Scoring rules:
     * <ul>
     *   <li>anomaly detected → score += 0.2, status → TESTING</li>
     *   <li>WAF blocked → score -= 0.05 (protected but may still be vulnerable)</li>
     *   <li>normal response → score -= 0.15</li>
     *   <li>confirmed vulnerability → score = 1.0, status → CONFIRMED</li>
     *   <li>score below PRUNE_THRESHOLD → status → PRUNED</li>
     * </ul>
     *
     * @param hypothesisId the hypothesis ID to update
     * @param testResult   the raw test result string
     * @return the updated hypothesis, or null if not found
     */
    public Hypothesis updateScore(String hypothesisId, String testResult) {
        Hypothesis h = hypotheses.get(hypothesisId);
        if (h == null) return null;

        boolean hasAnomaly = testResult != null && (
                testResult.contains("\"anomaly\":true")
                || testResult.contains("SQL 错误") || testResult.contains("sql error")
                || testResult.contains("堆栈跟踪") || testResult.contains("stack trace")
                || testResult.contains("反射") || testResult.contains("reflect"));

        boolean isWafBlocked = testResult != null && (
                testResult.contains("waf_detected") || testResult.contains("\"waf_detected\":true")
                || testResult.contains("WAF"));

        boolean isConfirmed = testResult != null && (
                testResult.contains("confirmed") || testResult.contains("确认漏洞")
                || testResult.contains("vulnerability confirmed"));

        Hypothesis updated;
        if (isConfirmed) {
            updated = h.withScore(1.0)
                    .withStatus(HypothesisStatus.CONFIRMED)
                    .withAddedEvidence("漏洞已确认: " + truncate(testResult, 100));
        } else if (hasAnomaly) {
            updated = h.withScore(h.score() + 0.2)
                    .withStatus(HypothesisStatus.TESTING)
                    .withAddedEvidence("检测到异常响应: " + truncate(testResult, 80));
        } else if (isWafBlocked) {
            updated = h.withScore(h.score() - 0.05)
                    .withAddedEvidence("WAF 拦截（仍可能有漏洞）");
        } else {
            updated = h.withScore(h.score() - 0.15)
                    .withAddedEvidence("正常响应");
        }

        // Auto-prune if score is too low
        if (updated.score() < PRUNE_THRESHOLD && updated.status() != HypothesisStatus.CONFIRMED) {
            updated = updated.withStatus(HypothesisStatus.PRUNED);
        }

        hypotheses.put(hypothesisId, updated);
        return updated;
    }

    /**
     * Mark a hypothesis as TESTING (when the agent starts testing it).
     */
    public void markTesting(String hypothesisId) {
        Hypothesis h = hypotheses.get(hypothesisId);
        if (h != null && h.status() == HypothesisStatus.PENDING) {
            hypotheses.put(hypothesisId, h.withStatus(HypothesisStatus.TESTING));
        }
    }

    // ========== MERGE: Combine Related Hypotheses ==========

    /**
     * Merge two hypotheses that share a root cause into an attack chain.
     *
     * <p>GoT key advantage: when two separate branches discover related
     * vulnerabilities (e.g., IDOR on read + IDOR on write), merging them
     * creates a higher-impact attack chain.
     *
     * @param idA first hypothesis ID
     * @param idB second hypothesis ID
     * @return the merged hypothesis, or null if merge is not applicable
     */
    public Hypothesis merge(String idA, String idB) {
        Hypothesis a = hypotheses.get(idA);
        Hypothesis b = hypotheses.get(idB);
        if (a == null || b == null) return null;

        // Only merge if they share the same parameter or vuln type
        boolean sameParam = a.parameter().equals(b.parameter());
        boolean sameType = a.vulnType() == b.vulnType();

        if (!sameParam && !sameType) return null;

        String mergedId = String.format("H%02d", nextId++);
        List<String> mergedEvidence = new ArrayList<>(a.evidence());
        mergedEvidence.addAll(b.evidence());
        mergedEvidence.add(String.format("MERGE: %s(%s) + %s(%s) = 攻击链",
                a.vulnType().displayName(), a.parameter(),
                b.vulnType().displayName(), b.parameter()));

        // Merged hypothesis gets a score boost (chain > single)
        double mergedScore = Math.min(1.0, Math.max(a.score(), b.score()) + 0.15);

        Hypothesis merged = new Hypothesis(mergedId, a.vulnType(),
                a.parameter(), String.format("攻击链: %s → %s",
                        a.vulnType().displayName(), b.vulnType().displayName()),
                mergedScore, HypothesisStatus.TESTING, mergedEvidence);

        // Mark originals as merged
        hypotheses.put(idA, a.withStatus(HypothesisStatus.MERGED));
        hypotheses.put(idB, b.withStatus(HypothesisStatus.MERGED));
        hypotheses.put(mergedId, merged);

        logger.info("[HypothesisGen] 合并假设: %s + %s → %s (攻击链, score=%.2f)",
                idA, idB, mergedId, mergedScore);
        return merged;
    }

    // ========== Board Generation ==========

    /**
     * Build the hypothesis board for injection into messages.
     *
     * <p>Shows all hypotheses sorted by score (descending) with their
     * status icons, giving the agent a clear visual overview.
     *
     * @return formatted board string, or empty string if no hypotheses
     */
    public String buildHypothesisBoard() {
        if (hypotheses.isEmpty()) return "";

        StringBuilder sb = new StringBuilder("【攻击假设看板（GoT 模式）】\n");
        sb.append("按可行性评分排序。✅=已确认 ❓=疑似 🔄=测试中 ⏳=待测 ✗=已剪枝 🔗=已合并\n\n");

        // Sort by score descending, confirmed first
        List<Hypothesis> sorted = hypotheses.values().stream()
                .sorted((a, b) -> {
                    // Confirmed always first
                    if (a.status() == HypothesisStatus.CONFIRMED && b.status() != HypothesisStatus.CONFIRMED) return -1;
                    if (b.status() == HypothesisStatus.CONFIRMED && a.status() != HypothesisStatus.CONFIRMED) return 1;
                    // Then by score
                    return Double.compare(b.score(), a.score());
                })
                .toList();

        for (Hypothesis h : sorted) {
            sb.append(String.format("  %s [%s] %s @ %s — 评分: %.2f\n",
                    h.status().icon(), h.id(),
                    h.vulnType().displayName(), h.parameter(), h.score()));
            if (!h.evidence().isEmpty()) {
                String latestEvidence = h.evidence().get(h.evidence().size() - 1);
                sb.append(String.format("     最新: %s\n", truncate(latestEvidence, 80)));
            }
        }

        // Summary stats
        long active = hypotheses.values().stream()
                .filter(h -> h.status() != HypothesisStatus.PRUNED && h.status() != HypothesisStatus.MERGED)
                .count();
        long confirmed = hypotheses.values().stream()
                .filter(h -> h.status() == HypothesisStatus.CONFIRMED)
                .count();

        sb.append(String.format("\n活跃假设: %d | 已确认: %d | 总计: %d\n",
                active, confirmed, hypotheses.size()));

        sb.append("策略: 优先测试高分假设。连续 3 次失败后剪枝，转向下一个。\n");

        return sb.toString();
    }

    // ========== Query Methods ==========

    /**
     * Get the highest-scoring active (non-pruned, non-confirmed) hypothesis.
     * Used by the agent to decide what to test next.
     */
    public Hypothesis getTopHypothesis() {
        return hypotheses.values().stream()
                .filter(h -> h.status() == HypothesisStatus.PENDING
                        || h.status() == HypothesisStatus.TESTING)
                .max(Comparator.comparingDouble(Hypothesis::score))
                .orElse(null);
    }

    /**
     * Get all active hypotheses (not pruned, not merged).
     */
    public List<Hypothesis> getActiveHypotheses() {
        return hypotheses.values().stream()
                .filter(h -> h.status() != HypothesisStatus.PRUNED
                        && h.status() != HypothesisStatus.MERGED)
                .toList();
    }

    /**
     * Whether hypotheses have been generated.
     */
    public boolean isGenerated() {
        return generated;
    }

    /**
     * Get total hypothesis count.
     */
    public int size() {
        return hypotheses.size();
    }

    /**
     * Get a specific hypothesis by ID.
     */
    public Hypothesis get(String id) {
        return hypotheses.get(id);
    }

    // ========== Internal ==========

    private List<Hypothesis> parseHypotheses(String json) {
        try {
            // P1-1: route through JsonExtractor (same reason as
            // EpisodicReflectionMemory.parseReflection).
            var obj = com.flechazo.apisentinel.util.JsonExtractor.extract(json);
            if (obj == null) return new ArrayList<>();
            List<Hypothesis> result = new ArrayList<>();

            if (obj.has("hypotheses") && obj.get("hypotheses").isJsonArray()) {
                for (var elem : obj.getAsJsonArray("hypotheses")) {
                    if (!elem.isJsonObject()) continue;
                    var hObj = elem.getAsJsonObject();

                    String vulnTypeStr = getStr(hObj, "vuln_type", "OTHER");
                    VulnCategory vulnType = parseVulnCategory(vulnTypeStr);
                    double score = hObj.has("score") ? hObj.get("score").getAsDouble() : 0.5;

                    String id = String.format("H%02d", nextId++);
                    Hypothesis h = new Hypothesis(id, vulnType,
                            getStr(hObj, "parameter", "unknown"),
                            getStr(hObj, "rationale", ""),
                            Math.max(0.0, Math.min(1.0, score)),
                            HypothesisStatus.PENDING,
                            new ArrayList<>());
                    hypotheses.put(id, h);
                    result.add(h);
                }
            }

            return result;
        } catch (Exception e) {
            // P1-1: promote to warn — hypothesis parse failure means
            // the GoT-style hypothesis tree silently lost a branch;
            // subsequent plan-then-execute prioritization is working
            // on incomplete data.
            logger.warn("[HypothesisGen] 假设解析失败: %s", e.getMessage());
            return List.of();
        }
    }

    /**
     * Fallback: generate simple hypotheses from profile categories without LLM.
     */
    private List<Hypothesis> generateFallbackHypotheses(AnalysisProfile.ProfileResult profile) {
        List<Hypothesis> result = new ArrayList<>();
        for (VulnCategory cat : profile.priorityCategories()) {
            if (result.size() >= MAX_BRANCHES) break;
            String id = String.format("H%02d", nextId++);
            Hypothesis h = new Hypothesis(id, cat, "auto-detected",
                    String.format("Profile '%s' 标记为高优先级", profile.profileName()),
                    0.5, HypothesisStatus.PENDING, new ArrayList<>());
            hypotheses.put(id, h);
            result.add(h);
        }
        generated = true;
        logger.info("[HypothesisGen] 使用 fallback 生成 %d 个假设", result.size());
        return result;
    }

    private VulnCategory parseVulnCategory(String s) {
        try {
            return VulnCategory.valueOf(s.trim().toUpperCase());
        } catch (IllegalArgumentException e) {
            // Common aliases
            String upper = s.trim().toUpperCase();
            if (upper.contains("SQL")) return VulnCategory.SQL_INJECTION;
            if (upper.contains("AUTH")) return VulnCategory.AUTH_BYPASS;
            if (upper.contains("IDOR") || upper.contains("越权")) return VulnCategory.IDOR;
            if (upper.contains("TRAVERSAL") || upper.contains("PATH")) return VulnCategory.PATH_TRAVERSAL;
            if (upper.contains("CMD") || upper.contains("COMMAND") || upper.contains("RCE")) return VulnCategory.COMMAND_INJECTION;
            // Generic fallback
            return VulnCategory.INFO_DISCLOSURE;
        }
    }

    private String getStr(com.google.gson.JsonObject obj, String key, String defaultValue) {
        return obj.has(key) && !obj.get(key).isJsonNull()
                ? obj.get(key).getAsString() : defaultValue;
    }

    private static String truncate(String s, int max) {
        if (s == null) return "";
        s = s.strip();
        return s.length() <= max ? s : s.substring(0, max) + "...";
    }
}
