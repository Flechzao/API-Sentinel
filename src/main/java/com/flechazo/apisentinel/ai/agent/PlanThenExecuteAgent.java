package com.flechazo.apisentinel.ai.agent;

import com.flechazo.apisentinel.ai.provider.LlmProvider;
import com.flechazo.apisentinel.ai.provider.LlmRequest;
import com.flechazo.apisentinel.logging.LeveledLogger;
import com.flechazo.apisentinel.model.ApiEntry;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;

/**
 * Plan-then-Execute agent pattern — separates planning from execution.
 *
 * <p>Based on LangGraph StateGraph + Anthropic Orchestrator-Workers pattern.
 * Instead of having the LLM decide "what to do next" every iteration (which
 * wastes 30-40% of iterations on planning), we generate a structured analysis
 * plan once after reconnaissance, then follow it.
 *
 * <p>Flow:
 * <pre>
 * 1. heuristic_scan + fingerprint + code analysis (RECON phase)
 * 2. generatePlan() → structured analysis plan
 * 3. Inject plan into messages → agent follows it step by step
 * 4. Re-plan only when encountering major surprises
 * </pre>
 *
 * <p>Expected benefit: reduce planning overhead by 30-40%, more systematic analysis.
 */
public class PlanThenExecuteAgent {

    /**
     * A single step in the analysis plan.
     *
     * @param stepNumber      1-based step number
     * @param objective       what to test (e.g., "测试 /api/users/{id} 的 SQL 注入")
     * @param toolsToUse      which tools to use (e.g., "generate_payloads → send_request")
     * @param successCriteria what constitutes success (e.g., "响应差异或 SQL 错误")
     * @param fallback        what to do if this step fails
     */
    public record PlanStep(
            int stepNumber,
            String objective,
            String toolsToUse,
            String successCriteria,
            String fallback
    ) {}

    /**
     * A complete analysis plan.
     *
     * @param steps               ordered list of analysis steps
     * @param overallStrategy     high-level strategy description
     * @param estimatedIterations estimated total iterations needed
     */
    public record AnalysisPlan(
            List<PlanStep> steps,
            String overallStrategy,
            int estimatedIterations
    ) {}

    private final LeveledLogger logger;
    private AnalysisPlan currentPlan;
    private boolean planInjected = false;
    private int currentStepIndex = 0;
    /** Fast model name for cheap LLM calls (null = use main model). */
    private String fastModelName;

    public PlanThenExecuteAgent(LeveledLogger logger) {
        this.logger = logger;
    }

    /** Set the fast model name for cheap plan-generation LLM calls. */
    public void setFastModelName(String name) {
        this.fastModelName = name;
    }

    /**
     * Generate an analysis plan after reconnaissance is complete.
     *
     * <p>Called after heuristic_scan + fingerprint_components + code analysis
     * have returned results. Uses the LLM to produce a structured plan.
     *
     * @param entry       the API entry being analyzed
     * @param scanResult  heuristic_scan result summary
     * @param codeResult  code analysis result summary (may be empty)
     * @param profile     the analysis profile (from AnalysisProfile)
     * @param provider    LLM provider for plan generation
     * @return the generated plan, or null if generation failed
     */
    public AnalysisPlan generatePlan(ApiEntry entry, String scanResult,
                                      String codeResult,
                                      AnalysisProfile.ProfileResult profile,
                                      LlmProvider provider) {
        if (provider == null) return null;

        String method = entry.getHttpMethod() != null ? entry.getHttpMethod() : "GET";
        String path = entry.getApiPath() != null ? entry.getApiPath() : "unknown";

        String prompt = String.format("""
                基于以下侦察结果，为 API 安全分析生成一份结构化执行计划。

                ## 目标 API
                %s %s

                ## 分析 Profile
                类型: %s
                重点: %s

                ## 侦察结果摘要
                %s

                ## 代码分析摘要
                %s

                请输出严格 JSON 格式的分析计划（不要 markdown）：
                {
                  "strategy": "整体策略（一句话）",
                  "estimated_iterations": 20,
                  "steps": [
                    {
                      "step": 1,
                      "objective": "具体测试目标",
                      "tools": "要使用的工具链",
                      "success": "成功标准",
                      "fallback": "失败时的备选方案"
                    }
                  ]
                }

                规则：
                - 按漏洞可能性从高到低排列
                - 每个步骤对应一种漏洞类型
                - 最多 8 个步骤
                - 最后一步总是"综合所有发现，准备报告"
                """,
                method, path,
                profile.profileName(),
                profile.recommendation(),
                truncate(scanResult, 2000),
                truncate(codeResult, 2000));

        try {
            var request = new LlmRequest(
                    "你是 API 安全分析规划专家。输出严格 JSON。",
                    prompt, 2048);
            // Use fast model if configured (same provider, cheaper model)
            if (fastModelName != null && !fastModelName.isBlank()) {
                request = request.withModelOverride(fastModelName);
            }
            String response = provider.complete(request)
                    .get(60, TimeUnit.SECONDS)
                    .content();

            currentPlan = parsePlan(response);
            if (currentPlan != null) {
                logger.info("[PlanThenExecute] 生成计划: %d 个步骤, 预估 %d 轮迭代",
                        currentPlan.steps().size(), currentPlan.estimatedIterations());
            }
            return currentPlan;
        } catch (Exception e) {
            logger.warn("[PlanThenExecute] 计划生成失败: %s", e.getMessage());
            return null;
        }
    }

    /**
     * Build the plan prompt for injection into messages.
     * Called once when the plan is first generated.
     *
     * @return formatted plan prompt, or empty string if no plan
     */
    public String buildPlanPrompt() {
        if (currentPlan == null) return "";

        StringBuilder sb = new StringBuilder();
        sb.append("【分析计划 — 请按步骤执行】\n");
        sb.append("策略: ").append(currentPlan.overallStrategy()).append("\n");
        sb.append("预计迭代: ").append(currentPlan.estimatedIterations()).append("\n\n");

        for (PlanStep step : currentPlan.steps()) {
            sb.append(String.format("Step %d: %s\n", step.stepNumber(), step.objective()));
            sb.append(String.format("  工具: %s\n", step.toolsToUse()));
            sb.append(String.format("  成功标准: %s\n", step.successCriteria()));
            sb.append(String.format("  备选方案: %s\n\n", step.fallback()));
        }

        sb.append("执行规则:\n");
        sb.append("- 按计划逐步执行，每完成一步简要记录结果\n");
        sb.append("- 如果当前步骤连续 3 次失败，执行备选方案或跳到下一步\n");
        sb.append("- 如果发现计划外的漏洞线索，添加到计划末尾\n");
        sb.append("- 最后一步综合所有发现提交报告\n");

        planInjected = true;
        return sb.toString();
    }

    /**
     * Get the current plan.
     */
    public AnalysisPlan getCurrentPlan() {
        return currentPlan;
    }

    /**
     * Whether a plan has been generated and injected.
     */
    public boolean isPlanInjected() {
        return planInjected;
    }

    /**
     * Whether a plan has been generated.
     */
    public boolean hasPlan() {
        return currentPlan != null;
    }

    // ========== Internal ==========

    private AnalysisPlan parsePlan(String json) {
        try {
            // P1-1: route through JsonExtractor.
            var obj = com.flechazo.apisentinel.util.JsonExtractor.extract(json);
            if (obj == null) return null;

            String strategy = obj.has("strategy") ? obj.get("strategy").getAsString() : "通用安全分析";
            int estimatedIterations = obj.has("estimated_iterations")
                    ? obj.get("estimated_iterations").getAsInt() : 20;

            List<PlanStep> steps = new ArrayList<>();
            if (obj.has("steps") && obj.get("steps").isJsonArray()) {
                for (var elem : obj.getAsJsonArray("steps")) {
                    if (!elem.isJsonObject()) continue;
                    var stepObj = elem.getAsJsonObject();
                    steps.add(new PlanStep(
                            stepObj.has("step") ? stepObj.get("step").getAsInt() : steps.size() + 1,
                            getStr(stepObj, "objective", "未指定"),
                            getStr(stepObj, "tools", "send_request"),
                            getStr(stepObj, "success", "异常响应"),
                            getStr(stepObj, "fallback", "跳到下一步")
                    ));
                }
            }

            if (steps.isEmpty()) return null;
            return new AnalysisPlan(steps, strategy, estimatedIterations);
        } catch (Exception e) {
            // P1-1: promote to warn — plan parse failure means the
            // plan-then-execute agent silently fell back to no-plan
            // behaviour; the operator has no signal that the "think
            // before acting" step was skipped.
            logger.warn("[PlanThenExecute] 计划解析失败: %s", e.getMessage());
            return null;
        }
    }

    private String getStr(com.google.gson.JsonObject obj, String key, String defaultValue) {
        return obj.has(key) && !obj.get(key).isJsonNull()
                ? obj.get(key).getAsString() : defaultValue;
    }

    private static String truncate(String s, int max) {
        if (s == null) return "(无)";
        return s.length() <= max ? s : s.substring(0, max) + "...";
    }
}
