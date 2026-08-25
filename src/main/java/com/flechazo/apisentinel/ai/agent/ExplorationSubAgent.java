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
 * Lightweight, isolated ReAct loop for delegated exploration sub-tasks —
 * used by DispatchExploreAgentTool so the main AgentLoop can hand off a
 * broad/exploratory question ("find every place JWT is validated in this
 * repo") without the intermediate read_file/grep_repo noise polluting its
 * own context. Deliberately NOT AgentLoop: that class is bound to
 * ApiEntry -> PipelineResult/FinalVerdict and terminates on submit_report;
 * this one terminates on a plain-text final answer (no more tool calls),
 * has no UI callbacks, and runs a small bounded number of turns.
 */
public final class ExplorationSubAgent {

    public record Result(boolean success, String summary, int iterationsUsed,
                          List<String> toolsCalled, String error) {}

    private static final int MAX_ITERATIONS = 12;
    private static final int MAX_TOKENS_PER_TURN = 8192;
    private static final int THINKING_BUDGET_TOKENS = 3000;
    private static final double TEMPERATURE = 0.3;
    /** Smaller than AgentLoop's — this sub-task's scope is narrower. */
    private static final int TOOL_RESULT_LIMIT = 8000;
    private static final int LLM_CALL_TIMEOUT_SEC = 150;

    private ExplorationSubAgent() {}

    public static Result run(LlmProvider provider, AgentToolRegistry registry,
                              String task, LeveledLogger logger) {
        List<ChatMessage> messages = new ArrayList<>();
        messages.add(ChatMessage.system(buildSystemPrompt(task)));
        messages.add(ChatMessage.user(task));

        List<ToolDefinition> toolDefs = registry.getDefinitions();
        List<String> toolsCalled = new ArrayList<>();

        try {
            for (int iteration = 0; iteration < MAX_ITERATIONS; iteration++) {
                LlmRequest request = new LlmRequest(messages, toolDefs, TEMPERATURE, MAX_TOKENS_PER_TURN);
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
                            logger.info("[ExploreSubAgent] 调用工具: %s", tc.toolName());
                        }
                        String toolResult = registry.executeTool(tc.toolName(), tc.arguments());
                        String truncated = truncate(toolResult, TOOL_RESULT_LIMIT);
                        messages.add(ChatMessage.toolResult(tc.id(), truncated));
                    }
                    continue;
                }

                if (response.content() != null && !response.content().isBlank()) {
                    // No tool calls and there's text — treat as the final answer.
                    return new Result(true, response.content(), iteration + 1, toolsCalled, null);
                }

                if (response.finishReason() == LlmResponse.FinishReason.MAX_TOKENS) {
                    messages.add(ChatMessage.assistant(response.content() != null ? response.content() : ""));
                    messages.add(ChatMessage.user("回复被截断，请精简续写或直接给出最终结论文本。"));
                    continue;
                }

                // Empty content, no tool calls, not MAX_TOKENS — nudge and continue.
                messages.add(ChatMessage.user("请使用工具继续调查，或直接输出最终结论文本（不再调用工具）。"));
            }
        } catch (Exception e) {
            String msg = e.getMessage() != null ? e.getMessage() : e.getClass().getSimpleName();
            return new Result(false, null, MAX_ITERATIONS, toolsCalled, "探索异常: " + msg);
        }

        // Hit the iteration cap without a clean text-only finish — better to
        // return whatever partial evidence was gathered than a hard failure.
        String partial = lastAssistantText(messages);
        String summary = "[提示: 已达到探索轮次上限(" + MAX_ITERATIONS + ")，以下为未完全收尾的部分结论]\n\n"
                + (partial != null ? partial : "(未能提炼出文本结论，请查看 tools_called 了解已尝试的方向)");
        return new Result(true, summary, MAX_ITERATIONS, toolsCalled, null);
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
                你是一个专注的代码/流量探索助手，被主分析流程委派调查一个具体问题。

                任务: %s

                使用可用工具收集证据（都是免费的只读工具，不会发送任何 HTTP 请求）。
                一旦你有足够把握回答这个问题，直接输出一段纯文本最终结论——不要再调用工具。
                结论要具体、可核查：引用文件路径+行号、关键代码片段，给出明确结论而不是模糊猜测。
                如果调查后发现问题本身无法在只读范围内得出确定结论，也要说明查到了什么、卡在哪里。
                使用中文回复。
                """.formatted(task);
    }

    private static String truncate(String s, int max) {
        if (s == null) return "";
        return s.length() <= max ? s : s.substring(0, max) + "\n...[truncated]";
    }
}
