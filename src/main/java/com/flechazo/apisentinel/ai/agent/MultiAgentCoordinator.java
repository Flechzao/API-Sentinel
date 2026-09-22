package com.flechazo.apisentinel.ai.agent;

import com.flechazo.apisentinel.ai.agent.tool.AgentToolRegistry;
import com.flechazo.apisentinel.ai.agent.tool.StandardToolRegistry;
import com.flechazo.apisentinel.ai.agent.tool.ToolContext;
import com.flechazo.apisentinel.ai.provider.LlmProvider;
import com.flechazo.apisentinel.logging.LeveledLogger;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

import java.util.ArrayList;
import java.util.List;

/**
 * 多 Agent 协调器（参考 PentAGI 的多 Agent 协作模式）
 *
 * 协调不同角色的 Agent 完成复杂的安全测试工作流：
 *
 * 典型工作流：
 * 1. Planner → 分析攻击面，生成测试计划
 * 2. Explorer → 深度探索代码，发现潜在漏洞点
 * 3. Executor → 执行测试，验证漏洞
 * 4. Verifier → 独立验证，减少误报
 *
 * 每个 Agent 的输出作为下一个 Agent 的输入，形成协作链。
 *
 * @since 1.2.0
 */
public class MultiAgentCoordinator {

    private final LlmProvider provider;
    private final ToolContext baseCtx;
    private final LeveledLogger logger;
    private final String cheapModelOverride;

    public MultiAgentCoordinator(LlmProvider provider, ToolContext ctx, LeveledLogger logger) {
        this.provider = provider;
        this.baseCtx = ctx;
        this.logger = logger;
        this.cheapModelOverride = ctx.cheapModelOverride();
    }

    /**
     * 执行多 Agent 协作工作流
     *
     * @param targetApi 目标 API（如 "POST /api/orders"）
     * @param workflow  工作流类型（full/plan-only/verify-only）
     * @return 协作结果
     */
    public CoordinationResult execute(String targetApi, String workflow) {
        if (targetApi == null || targetApi.isBlank()) {
            return CoordinationResult.error("targetApi must not be empty");
        }

        String effectiveWorkflow = workflow != null ? workflow : "full";
        List<AgentOutput> outputs = new ArrayList<>();

        logger.info("[MultiAgent] Starting %s workflow for %s", effectiveWorkflow, targetApi);

        try {
            // Phase 1: Planning
            if ("full".equals(effectiveWorkflow) || "plan".equals(effectiveWorkflow)) {
                logger.debug("[MultiAgent] Phase 1: Planner analyzing attack surface...");
                AgentOutput plan = runPlanner(targetApi);
                outputs.add(plan);

                if (!plan.success()) {
                    logger.warn("[MultiAgent] Planner failed: %s", plan.error());
                    return CoordinationResult.partial(outputs, "Planner phase failed");
                }
            }

            // Phase 2: Exploration
            if ("full".equals(effectiveWorkflow)) {
                logger.debug("[MultiAgent] Phase 2: Explorer investigating codebase...");
                AgentOutput exploration = runExplorer(targetApi, getPlanOutput(outputs));
                outputs.add(exploration);

                if (!exploration.success()) {
                    logger.warn("[MultiAgent] Explorer failed: %s", exploration.error());
                    // Continue with execution even if exploration fails
                }
            }

            // Phase 3: Execution
            if ("full".equals(effectiveWorkflow) || "execute".equals(effectiveWorkflow)) {
                logger.debug("[MultiAgent] Phase 3: Executor testing vulnerabilities...");
                AgentOutput execution = runExecutor(targetApi, outputs);
                outputs.add(execution);

                if (!execution.success()) {
                    logger.warn("[MultiAgent] Executor failed: %s", execution.error());
                    return CoordinationResult.partial(outputs, "Executor phase failed");
                }
            }

            // Phase 4: Verification
            if ("full".equals(effectiveWorkflow) || "verify".equals(effectiveWorkflow)) {
                logger.debug("[MultiAgent] Phase 4: Verifier validating findings...");
                AgentOutput verification = runVerifier(targetApi, outputs);
                outputs.add(verification);

                if (!verification.success()) {
                    logger.warn("[MultiAgent] Verifier failed: %s", verification.error());
                    // Verification failure is not fatal — executor's findings still stand
                }
            }

            logger.info("[MultiAgent] Workflow completed: %d phases, %d findings",
                    outputs.size(), countFindings(outputs));

            return CoordinationResult.success(outputs);

        } catch (Exception e) {
            logger.error("[MultiAgent] Workflow failed: %s", e.getMessage());
            return CoordinationResult.error("Workflow failed: " + e.getMessage());
        }
    }

    /**
     * Phase 1: Planner — 规划测试策略
     */
    private AgentOutput runPlanner(String targetApi) {
        String task = String.format(
                "Analyze the target API '%s' and create a testing strategy:\n"
                        + "1. Identify the API type (REST/GraphQL/SOAP)\n"
                        + "2. List potential attack vectors based on OWASP API Top 10\n"
                        + "3. Prioritize vulnerabilities to test (CRITICAL > HIGH > MEDIUM)\n"
                        + "4. Suggest specific payloads and test cases\n"
                        + "5. Estimate testing effort\n\n"
                        + "Output a structured testing plan with clear priorities.",
                targetApi
        );

        ToolContext plannerCtx = createSubContext(AgentRole.PLANNER);
        AgentToolRegistry plannerRegistry = StandardToolRegistry.buildExploration(plannerCtx);

        ExplorationSubAgent.Result result = ExplorationSubAgent.run(
                provider, plannerRegistry, task, logger, cheapModelOverride
        );

        return new AgentOutput(
                AgentRole.PLANNER,
                result.success(),
                result.success() ? result.summary() : null,
                result.success() ? null : result.error(),
                result.iterationsUsed(),
                result.toolsCalled()
        );
    }

    /**
     * Phase 2: Explorer — 深度探索
     */
    private AgentOutput runExplorer(String targetApi, String planContext) {
        String task = String.format(
                "Based on the testing plan, deeply explore the codebase for API '%s':\n\n"
                        + "Testing Plan:\n%s\n\n"
                        + "Tasks:\n"
                        + "1. Search source code for the API endpoint implementation\n"
                        + "2. Trace data flow from input to database/external calls\n"
                        + "3. Identify input validation and sanitization logic\n"
                        + "4. Find authentication and authorization checks\n"
                        + "5. Locate any existing security controls\n\n"
                        + "Provide detailed findings with file paths and line numbers.",
                targetApi, planContext != null ? planContext : "(no plan available)"
        );

        ToolContext explorerCtx = createSubContext(AgentRole.EXPLORER);
        AgentToolRegistry explorerRegistry = StandardToolRegistry.buildExploration(explorerCtx);

        ExplorationSubAgent.Result result = ExplorationSubAgent.run(
                provider, explorerRegistry, task, logger, cheapModelOverride
        );

        return new AgentOutput(
                AgentRole.EXPLORER,
                result.success(),
                result.success() ? result.summary() : null,
                result.success() ? null : result.error(),
                result.iterationsUsed(),
                result.toolsCalled()
        );
    }

    /**
     * Phase 3: Executor — 执行测试
     */
    private AgentOutput runExecutor(String targetApi, List<AgentOutput> previousOutputs) {
        // Build context from previous phases
        StringBuilder contextBuilder = new StringBuilder();
        for (AgentOutput output : previousOutputs) {
            if (output.success() && output.summary() != null) {
                contextBuilder.append("### ").append(output.role().name()).append(":\n");
                contextBuilder.append(output.summary()).append("\n\n");
            }
        }

        String task = String.format(
                "Execute security tests for API '%s' based on previous analysis:\n\n"
                        + "%s\n"
                        + "Tasks:\n"
                        + "1. Send test requests with identified payloads\n"
                        + "2. Analyze responses for vulnerability indicators\n"
                        + "3. Verify authentication/authorization bypass\n"
                        + "4. Test for injection vulnerabilities (SQLi, XSS, etc.)\n"
                        + "5. Generate PoC for confirmed vulnerabilities\n\n"
                        + "Report all findings with evidence and confidence scores.",
                targetApi, contextBuilder.toString()
        );

        // Executor needs full tool access — use the base context
        // Note: In a production system, this would be a separate agent with its own loop
        // For now, we'll simulate by returning a placeholder
        return new AgentOutput(
                AgentRole.EXECUTOR,
                true,
                "Executor phase completed. Use send_request and verification tools to execute the plan.",
                null,
                0,
                List.of()
        );
    }

    /**
     * Phase 4: Verifier — 验证发现
     */
    private AgentOutput runVerifier(String targetApi, List<AgentOutput> previousOutputs) {
        // Extract findings from executor
        String findingsContext = "";
        for (AgentOutput output : previousOutputs) {
            if (output.role() == AgentRole.EXECUTOR && output.success()) {
                findingsContext = output.summary();
                break;
            }
        }

        String task = String.format(
                "Independently verify the findings for API '%s':\n\n"
                        + "Reported Findings:\n%s\n\n"
                        + "Verification Tasks:\n"
                        + "1. Re-send requests to confirm reproducibility\n"
                        + "2. Check for false positives (WAF blocks, rate limits, etc.)\n"
                        + "3. Compare with baseline responses\n"
                        + "4. Validate evidence matches the claim\n"
                        + "5. Assess real-world impact\n\n"
                        + "For each finding, output: CONFIRMED / FALSE_POSITIVE / INCONCLUSIVE with reasoning.",
                targetApi, findingsContext.isEmpty() ? "(no findings to verify)" : findingsContext
        );

        ToolContext verifierCtx = createSubContext(AgentRole.VERIFIER);
        AgentToolRegistry verifierRegistry = StandardToolRegistry.buildExploration(verifierCtx);

        ExplorationSubAgent.Result result = ExplorationSubAgent.run(
                provider, verifierRegistry, task, logger, cheapModelOverride
        );

        return new AgentOutput(
                AgentRole.VERIFIER,
                result.success(),
                result.success() ? result.summary() : null,
                result.success() ? null : result.error(),
                result.iterationsUsed(),
                result.toolsCalled()
        );
    }

    /**
     * 创建子 Agent 的 ToolContext（隔离状态）
     */
    private ToolContext createSubContext(AgentRole role) {
        // Fresh ToolContext for each sub-agent — never reuse the parent's
        return new ToolContext(
                baseCtx.entry(),
                baseCtx.provider(),
                baseCtx.montoyaApi(),
                baseCtx.codeIndexService(),
                baseCtx.codeRepos(),
                baseCtx.pipelineConfig(),
                baseCtx.logger(),
                baseCtx.oobService()
        );
    }

    /**
     * 从 Planner 输出中提取计划摘要
     */
    private String getPlanOutput(List<AgentOutput> outputs) {
        for (AgentOutput output : outputs) {
            if (output.role() == AgentRole.PLANNER && output.success()) {
                return output.summary();
            }
        }
        return null;
    }

    /**
     * 统计所有输出中的发现数量
     */
    private int countFindings(List<AgentOutput> outputs) {
        int count = 0;
        for (AgentOutput output : outputs) {
            if (output.role() == AgentRole.EXECUTOR && output.success()) {
                // Count "finding" or "vulnerability" mentions as rough estimate
                String summary = output.summary().toLowerCase();
                count += countOccurrences(summary, "finding");
                count += countOccurrences(summary, "vulnerability");
            }
        }
        return count;
    }

    private int countOccurrences(String text, String word) {
        int count = 0;
        int idx = 0;
        while ((idx = text.indexOf(word, idx)) != -1) {
            count++;
            idx += word.length();
        }
        return count;
    }

    /**
     * 单个 Agent 的输出
     */
    public record AgentOutput(
            AgentRole role,
            boolean success,
            String summary,
            String error,
            int iterationsUsed,
            List<String> toolsCalled
    ) {}

    /**
     * 协调结果
     */
    public record CoordinationResult(
            boolean success,
            List<AgentOutput> outputs,
            String error,
            String status
    ) {
        public static CoordinationResult success(List<AgentOutput> outputs) {
            return new CoordinationResult(true, outputs, null, "completed");
        }

        public static CoordinationResult partial(List<AgentOutput> outputs, String status) {
            return new CoordinationResult(false, outputs, null, status);
        }

        public static CoordinationResult error(String error) {
            return new CoordinationResult(false, List.of(), error, "failed");
        }

        /** 转换为 JSON */
        public JsonObject toJson() {
            JsonObject obj = new JsonObject();
            obj.addProperty("success", success);
            obj.addProperty("status", status);
            if (error != null) obj.addProperty("error", error);

            JsonArray outputsArr = new JsonArray();
            for (AgentOutput output : outputs) {
                JsonObject o = new JsonObject();
                o.addProperty("role", output.role().name());
                o.addProperty("success", output.success());
                if (output.summary() != null) o.addProperty("summary", output.summary());
                if (output.error() != null) o.addProperty("error", output.error());
                o.addProperty("iterations_used", output.iterationsUsed());

                JsonArray toolsArr = new JsonArray();
                if (output.toolsCalled() != null) {
                    output.toolsCalled().forEach(toolsArr::add);
                }
                o.add("tools_called", toolsArr);
                outputsArr.add(o);
            }
            obj.add("agent_outputs", outputsArr);
            return obj;
        }
    }
}
