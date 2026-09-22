package com.flechazo.apisentinel.ai.agent;

import com.flechazo.apisentinel.ai.agent.tool.AgentToolRegistry;
import com.flechazo.apisentinel.ai.provider.ChatMessage;
import com.flechazo.apisentinel.ai.provider.LlmProvider;
import com.flechazo.apisentinel.ai.provider.LlmRequest;
import com.flechazo.apisentinel.ai.provider.LlmResponse;
import com.flechazo.apisentinel.ai.provider.ToolCall;
import com.flechazo.apisentinel.ai.provider.ToolDefinition;
import com.flechazo.apisentinel.logging.LeveledLogger;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;

/**
 * Isolated ReAct loop for delegated cluster hunting — used by ChainHunterTool
 * after the main AgentLoop confirms/suspects bug A on the current endpoint.
 * Mirrors ExplorationSubAgent's shape but, critically, is NOT read-only: it
 * may send real HTTP requests (via the shared parent SendRequestTool, so every
 * request lands in the parent's PayloadResults and flows through
 * VerdictValidator like any other evidence) and it maps sibling endpoints
 * (map_sibling_endpoints). It deliberately cannot: generate payloads via LLM,
 * submit reports, or spawn further sub-agents — final grading stays with the
 * parent, whose report gate (heuristic_scan, verify-count, identity audit)
 * applies unchanged. Terminates on a plain-text report, runs a bounded number
 * of turns.
 */
public final class ChainHunterSubAgent {

    public record Result(boolean success, String summary, int iterationsUsed,
                         List<String> toolsCalled, String error) {}

    /** Larger than ExplorationSubAgent's 12 — testing N siblings with real
     *  requests needs more turns than pure reading — but well below
     *  AgentLoop's 50 since this is one focused sub-task, not a full analysis. */
    // P2-3: reduced from 25 to 10 — the audit found a single chain_hunter
    // call can burn 30-80K tokens (30-70% of the main analysis). 25
    // iterations is excessive for a sub-agent that's supposed to be a
    // focused "follow this one chain" task. 10 is enough to trace a
    // 3-5 hop call chain with retries.
    private static final int MAX_ITERATIONS = 10;
    // P2-3: reduced from 8192 to 4096 — sub-agents should produce
    // concise focused output, not full analysis reports. 4096 is enough
    // for 3-5 findings with evidence.
    private static final int MAX_TOKENS_PER_TURN = 4096;
    private static final int THINKING_BUDGET_TOKENS = 3000;
    private static final double TEMPERATURE = 0.3;
    private static final int TOOL_RESULT_LIMIT = 16000;
    private static final int LLM_CALL_TIMEOUT_SEC = 150;

    private ChainHunterSubAgent() {}

    public static Result run(LlmProvider provider, AgentToolRegistry registry,
                             String task, LeveledLogger logger) {
        return run(provider, registry, task, logger, MAX_ITERATIONS, java.util.Set.of());
    }

    public static Result run(LlmProvider provider, AgentToolRegistry registry,
                             String task, LeveledLogger logger,
                             int maxIterations, java.util.Set<String> alreadyTestedPaths) {
        return run(provider, registry, task, logger, maxIterations, alreadyTestedPaths, null);
    }

    /** @param modelOverride low-cost model for this cluster-hunting loop (cost
     *  tiering); null = main model. */
    public static Result run(LlmProvider provider, AgentToolRegistry registry,
                             String task, LeveledLogger logger,
                             int maxIterations, java.util.Set<String> alreadyTestedPaths,
                             String modelOverride) {
        int effectiveMax = maxIterations > 0 ? Math.min(maxIterations, 20) : MAX_ITERATIONS;
        List<ChatMessage> messages = new ArrayList<>();
        String dedupNote = alreadyTestedPaths.isEmpty() ? "" :
                "\n\n## 已测端点（无需重复测试）\n" + String.join(", ", alreadyTestedPaths);
        messages.add(ChatMessage.system(buildSystemPrompt(task + dedupNote)));
        messages.add(ChatMessage.user(task));

        List<ToolDefinition> toolDefs = registry.getDefinitions();
        List<String> toolsCalled = new ArrayList<>();

        try {
            for (int iteration = 0; iteration < effectiveMax; iteration++) {
                LlmRequest request = new LlmRequest(messages, toolDefs, TEMPERATURE, MAX_TOKENS_PER_TURN);
                if (modelOverride != null && !modelOverride.isBlank()) {
                    request = request.withModelOverride(modelOverride);
                }
                if (provider.supportsExtendedThinking()) {
                    request = request.withThinking(THINKING_BUDGET_TOKENS);
                }

                LlmResponse response = provider.complete(request).get(LLM_CALL_TIMEOUT_SEC, TimeUnit.SECONDS);

                if (response.finishReason() == LlmResponse.FinishReason.ERROR
                        || response.finishReason() == LlmResponse.FinishReason.RATE_LIMITED) {
                    return new Result(false, null, iteration, toolsCalled,
                            "LLM 调用失败: " + response.errorMessage());
                }

                if (response.hasToolCalls()) {
                    messages.add(ChatMessage.assistantWithToolCalls(
                            response.content(), response.toolCalls(), response.rawThinkingBlocksJson()));

                    for (ToolCall tc : response.toolCalls()) {
                        toolsCalled.add(tc.toolName());
                        if (logger != null) {
                            logger.info("[ChainHunterSubAgent] 调用工具: %s", tc.toolName());
                        }
                        String toolResult = registry.executeTool(tc.toolName(), tc.arguments());
                        String truncated = truncate(toolResult, TOOL_RESULT_LIMIT);
                        messages.add(ChatMessage.toolResult(tc.id(), truncated));
                    }
                    continue;
                }

                if (response.content() != null && !response.content().isBlank()) {
                    // No tool calls and there's text — treat as the final report.
                    return new Result(true, response.content(), iteration + 1, toolsCalled, null);
                }

                if (response.finishReason() == LlmResponse.FinishReason.MAX_TOKENS) {
                    messages.add(ChatMessage.assistant(response.content() != null ? response.content() : ""));
                    messages.add(ChatMessage.user("回复被截断，请精简续写或直接给出最终报告文本。"));
                    continue;
                }

                // Empty content, no tool calls, not MAX_TOKENS — nudge and continue.
                messages.add(ChatMessage.user("请使用工具继续测试，或直接输出最终报告文本（不再调用工具）。"));
            }
        } catch (Exception e) {
            String msg = e.getMessage() != null ? e.getMessage() : e.getClass().getSimpleName();
            return new Result(false, null, effectiveMax, toolsCalled, "集群狩猎异常: " + msg);
        }

        // Hit the iteration cap without a clean text-only finish — return the
        // partial evidence gathered so far rather than a hard failure.
        String partial = lastAssistantText(messages);
        String summary = "[提示: 已达到集群狩猎轮次上限(" + effectiveMax + ")，以下为未完全收尾的部分结论]\n\n"
                + (partial != null ? partial : "(未能提炼出文本结论，请查看 tools_called 了解已测试的方向)");
        return new Result(true, summary, effectiveMax, toolsCalled, null);
    }

    private static String lastAssistantText(List<ChatMessage> messages) {
        for (int i = messages.size() - 1; i >= 0; i--) {
            ChatMessage m = messages.get(i);
            if ("assistant".equals(m.role()) && m.content() != null && !m.content().isBlank()) {
                return m.content();
            }
        }
        return null;
    }

    private static String buildSystemPrompt(String task) {
        return """
                你是一个集群狩猎子代理。主分析流程已在目标接口确认/疑似漏洞 A，你的任务是：
                把 A 的攻击模式系统性扩散到兄弟端点，并尝试 A→B 串链发现。

                任务: %s

                ## 工作方式（六步法）
                1. map_sibling_endpoints 获取兄弟端点清单（同 Controller/同资源前缀；写方法标了 priority=high）
                2. 需要理解兄弟端点实现时用 read_file/grep_repo 快速确认（鉴权检查是否同样缺失）
                3. 用 send_request 把 A 的攻击模式逐个实测到兄弟端点上（写方法优先）；越权类配合
                   test_auth_bypass 做会话交换比对；响应拿不准时用 diff_responses 对比基线；
                   SSRF 场景下用 generate_oob_probe 生成探针域名、check_oob_results 查回连
                4. 兄弟端点暴露不同漏洞类时，描述 A+B 串链的可能性并实测关键环节
                5. 每个端点记录：方法+路径、关键请求、响应差异、结论

                ## 约束
                - 只扩散 A 的同类攻击模式 + 直接可串的链，不做全面重扫（那是主分析的事）
                - 兄弟端点全部 401/403/404 或响应无差异 → 如实报告"未扩散"，这是有价值的结论，
                  不代表白跑
                - 节奏纪律：同一端点最多 2 轮无新线索就跳到下一个；注意 send_request 内置限速
                - 你的结论是情报不是终审：疑似漏洞要给出具体证据（状态码/响应差异/数据内容），
                  最终定级由主分析决定
                - 构造请求前先用 search_traffic/list_sessions 找可复用的认证头，避免无凭据盲测

                ## 结束时输出纯文本报告（不再调用工具），格式：
                ## 测试覆盖（N 个兄弟端点）
                - METHOD path → 结论（可利用/无差异/无权限/WAF拦截/…）+ 关键证据（状态码/响应片段）
                ## 链式发现（如有）
                - A→B 链路描述，每环附证据
                ## 建议
                - 需要主分析进一步验证/定级的点
                使用中文。
                """.formatted(task);
    }

    private static String truncate(String s, int max) {
        if (s == null) return "";
        return s.length() <= max ? s : s.substring(0, max) + "\n...[truncated]";
    }
}
