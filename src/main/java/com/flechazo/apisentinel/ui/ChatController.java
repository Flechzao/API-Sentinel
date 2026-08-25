package com.flechazo.apisentinel.ui;

import burp.api.montoya.MontoyaApi;
import com.flechazo.apisentinel.ai.pipeline.PayloadResult;
import com.flechazo.apisentinel.ai.pipeline.PipelineConfig;
import com.flechazo.apisentinel.ai.provider.ChatMessage;
import com.flechazo.apisentinel.ai.provider.LlmProvider;
import com.flechazo.apisentinel.ai.provider.LlmProviderFactory;
import com.flechazo.apisentinel.ai.provider.LlmRequest;
import com.flechazo.apisentinel.ai.provider.LlmResponse;
import com.flechazo.apisentinel.ai.provider.ToolCall;
import com.flechazo.apisentinel.ai.provider.ToolDefinition;
import com.flechazo.apisentinel.codeindex.CodeIndexService;
import com.flechazo.apisentinel.config.ConfigManager;
import com.flechazo.apisentinel.detection.OobService;
import com.flechazo.apisentinel.logging.LeveledLogger;
import com.flechazo.apisentinel.model.ApiEntry;

import javax.swing.SwingUtilities;
import java.util.List;
import java.util.concurrent.TimeUnit;

/**
 * Chat controller for the embedded AiChatPanel (one conversation per API path).
 */
/** AI 对话控制器——管理嵌入式聊天面板的一次对话（含工具调用循环）。 */
class ChatController {

    private final MontoyaApi api;
    private final ConfigManager configManager;
    private final CodeIndexService codeIndexService;
    private final LlmProviderFactory providerFactory;
    private final OobService oobService;
    private final AnalysisContextLookup contextLookup;
    private final LeveledLogger logger;

    private ApiSentinelTab view;
    /** Inline chat cards (sandbox confirm / ask_user) for tool-calling chats. */
    private com.flechazo.apisentinel.ai.agent.tool.UserInteractionBridge interactionBridge;

    ChatController(MontoyaApi api, ConfigManager configManager, CodeIndexService codeIndexService,
                   LlmProviderFactory providerFactory, OobService oobService,
                   AnalysisContextLookup contextLookup, LeveledLogger logger) {
        this.api = api;
        this.configManager = configManager;
        this.codeIndexService = codeIndexService;
        this.providerFactory = providerFactory;
        this.oobService = oobService;
        this.contextLookup = contextLookup;
        this.logger = logger;
    }

    void setView(ApiSentinelTab view) { this.view = view; }

    void setInteractionBridge(com.flechazo.apisentinel.ai.agent.tool.UserInteractionBridge bridge) {
        this.interactionBridge = bridge;
    }

    // ======================== Embedded chat tab ========================

    public void onChatMessage(String message) {
        if (message == null || message.isBlank() || view == null) return;

        AiChatPanel chatPanel = view.getAiChatPanel();
        chatPanel.showThinking();

        com.flechazo.apisentinel.util.SharedTaskPool.submitInteractive(() -> {
            try {
                LlmProvider provider = providerFactory.getFirstAvailable();
                if (provider == null) {
                    SwingUtilities.invokeLater(() ->
                            chatPanel.replaceLastAiMessage("错误: 无可用的 AI Provider，请在设置中配置。"));
                    return;
                }

                String sysPrompt = buildChatSystemPrompt(chatPanel);
                ApiEntry entry = chatPanel.getCurrentEntry();

                if (provider.supportsToolCalling() && entry != null) {
                    runEmbeddedToolCallingChat(provider, entry, chatPanel, sysPrompt, message);
                } else {
                    runEmbeddedSimpleChat(provider, chatPanel, sysPrompt, message);
                }
            } catch (Exception e) {
                logger.error("Chat 请求失败: %s", e.getMessage());
                String errMsg = e.getMessage() != null ? e.getMessage() : e.getClass().getSimpleName();
                SwingUtilities.invokeLater(() -> chatPanel.replaceLastAiMessage("请求失败: " + errMsg));
            }
        });
    }

    private String buildChatSystemPrompt(AiChatPanel chatPanel) {
        StringBuilder systemPrompt = new StringBuilder();
                systemPrompt.append("你是 API Sentinel 安全分析助手，专注于 API 接口安全风险分析。\n");
                systemPrompt.append("重要规则：下方已提供当前接口的完整信息（包括请求、响应、分析记录等），");
                systemPrompt.append("请直接基于这些信息回答用户问题，不要再向用户索要这些已有数据。\n");
                systemPrompt.append("回答要求：专业、具体、可操作。使用中文回答。\n");
                systemPrompt.append("你可以使用工具来实际发送请求验证漏洞，不要只是描述步骤让用户自己操作。\n\n");

                ApiEntry entry = chatPanel.getCurrentEntry();
                if (entry != null) {
                    systemPrompt.append("========== 当前接口完整信息 ==========\n");
                    systemPrompt.append("HTTP方法: ").append(entry.getHttpMethod()).append("\n");
                    systemPrompt.append("路径: ").append(entry.getApiPath()).append("\n");
                    systemPrompt.append("域名: ").append(entry.getDomain().isEmpty() ? "未知" : entry.getDomain()).append("\n");
                    systemPrompt.append("状态: ").append(entry.getStatus()).append("\n");

                    if (entry.hasTrafficData()) {
                        systemPrompt.append("\n--- 最近流量数据 ---\n");
                        systemPrompt.append("完整URL: ").append(entry.getLastUrl()).append("\n");
                        systemPrompt.append("响应状态码: ").append(entry.getLastStatusCode()).append("\n");
                        String rawReq = entry.getLastRawRequest();
                        if (rawReq.length() > 3000) rawReq = rawReq.substring(0, 3000) + "\n...[截断]";
                        systemPrompt.append("\n请求报文:\n```\n").append(rawReq).append("\n```\n");
                        String rawResp = entry.getLastRawResponse();
                        if (rawResp.length() > 3000) rawResp = rawResp.substring(0, 3000) + "\n...[截断]";
                        systemPrompt.append("\n响应报文:\n```\n").append(rawResp).append("\n```\n");
                    } else {
                        chatPanel.appendProgressNote("🔍 未发现已捕获的实时流量，正在检索 Burp History...");
                        var lookup = contextLookup.gatherHistoryContextDetailed(entry);
                        if (lookup.matchCount() > 0) {
                            chatPanel.appendProgressNote(String.format(
                                    "✓ 已扫描 Burp History 共 %d 条记录，筛选后匹配到 %d 条",
                                    lookup.totalScanned(), lookup.matchCount()));
                            systemPrompt.append("\n--- 已扫描 Burp History 共 ").append(lookup.totalScanned())
                                    .append(" 条记录，筛选后匹配到 ").append(lookup.matchCount()).append(" 条 ---\n");
                            systemPrompt.append(lookup.contextText());
                        } else {
                            chatPanel.appendProgressNote(String.format(
                                    "⚠ 已扫描 Burp History 共 %d 条记录，未找到匹配该接口的记录", lookup.totalScanned()));
                            systemPrompt.append(String.format(
                                    "\n（该接口尚无流量数据：已扫描 Burp Proxy History 共 %d 条记录，"
                                    + "未在实时捕获流量和 History 中找到匹配记录。"
                                    + "可能原因：1) 该接口尚未被实际访问过；2) 路径匹配规则未命中；3) 该请求发生在 Burp History 范围之外。"
                                    + "如需分析，请先通过浏览器/客户端实际触发一次该接口的请求。）\n",
                                    lookup.totalScanned()));
                        }
                    }

                    var latestRecord = entry.getLatestAnalysisRecord();
                    if (latestRecord != null && latestRecord.result() != null && latestRecord.result().isSuccess()) {
                        systemPrompt.append("\n--- AI分析历史记录 ---\n");
                        systemPrompt.append("风险等级: ").append(latestRecord.result().overallRisk()).append("\n");
                        systemPrompt.append("分析摘要: ").append(latestRecord.result().summary()).append("\n");
                        var findings = latestRecord.result().findings();
                        if (!findings.isEmpty()) {
                            systemPrompt.append("发现 ").append(findings.size()).append(" 个安全问题:\n");
                            for (int i = 0; i < Math.min(findings.size(), 5); i++) {
                                var f = findings.get(i);
                                systemPrompt.append("  ").append(i + 1).append(". [")
                                        .append(f.risk()).append("] ").append(f.title())
                                        .append(" (").append(f.type()).append(")\n");
                            }
                        }
                    }
                    systemPrompt.append("========== 接口信息结束 ==========\n");
                } else {
                    systemPrompt.append("（当前未选择具体接口，用户可能在进行通用安全咨询）\n");
                }
        return systemPrompt.toString();
    }

    private void runEmbeddedSimpleChat(LlmProvider provider, AiChatPanel chatPanel,
                                        String systemPromptStr, String message) throws Exception {
        StringBuilder conversationContext = new StringBuilder();
        var history = chatPanel.getCurrentHistory();
        int startIdx = Math.max(0, history.size() - 10);
        for (int i = startIdx; i < history.size(); i++) {
            var msg = history.get(i);
            if ("user".equals(msg.role())) {
                conversationContext.append("User: ").append(msg.content()).append("\n");
            } else if ("assistant".equals(msg.role())) {
                conversationContext.append("Assistant: ").append(msg.content()).append("\n");
            }
        }

        String userPrompt = conversationContext.isEmpty()
                ? message
                : "对话历史:\n" + conversationContext + "\n当前问题: " + message;

        LlmRequest request = new LlmRequest(systemPromptStr, userPrompt, 0.7, 4096, "text");
        LlmResponse response = provider.complete(request).get(90, TimeUnit.SECONDS);

        String reply = response.isSuccess() ? response.content()
                : "请求失败: " + (response.errorMessage() != null ? response.errorMessage() : "未知错误");
        SwingUtilities.invokeLater(() -> chatPanel.replaceLastAiMessage(reply));
    }

    private void runEmbeddedToolCallingChat(LlmProvider provider, ApiEntry entry,
                                             AiChatPanel chatPanel, String systemPromptStr, String message) throws Exception {
        var appConfig = configManager.getConfig();
        boolean authTestEnabled = appConfig.isUnauthorizedDetectionEnabled();
        PipelineConfig pipelineConfig = new PipelineConfig(true, 10, true, authTestEnabled,
                appConfig.getAuthSessionACookie(), appConfig.getAuthSessionALabel(),
                appConfig.getAuthSessionBCookie(), appConfig.getAuthSessionBLabel(),
                appConfig.getContextWindowTokens(), true,
                appConfig.isWafDetectionEnabled(), appConfig.isWafRetryEnabled(),
                appConfig.isActiveProbeEnabled(), appConfig.isBlindVerificationEnabled(),
                appConfig.getMaxBlindProbeRequests(),
                appConfig.isBusinessLogicVerificationEnabled(),
                appConfig.isAiAuthArbitrationEnabled())
                .withAuditHighRiskOnly(appConfig.isAuditHighRiskOnly())
                .withCodeExecutionAutoApprove(appConfig.isCodeExecutionAutoApprove());

        com.flechazo.apisentinel.ai.agent.tool.ToolContext toolCtx =
                new com.flechazo.apisentinel.ai.agent.tool.ToolContext(
                        entry, provider, api, codeIndexService,
                        appConfig.getCodeRepos(), pipelineConfig, logger, oobService);
        if (interactionBridge != null) toolCtx.setUserInteractionBridge(interactionBridge);

        com.flechazo.apisentinel.ai.agent.tool.AgentToolRegistry registry =
                com.flechazo.apisentinel.ai.agent.tool.StandardToolRegistry.build(toolCtx, false).registry();

        List<ToolDefinition> toolDefs = registry.getDefinitions();

        List<ChatMessage> messages = new java.util.ArrayList<>();
        messages.add(ChatMessage.system(systemPromptStr));

        var panelHistory = chatPanel.getCurrentHistory();
        int startIdx = Math.max(0, panelHistory.size() - 10);
        for (int i = startIdx; i < panelHistory.size(); i++) {
            var msg = panelHistory.get(i);
            if ("user".equals(msg.role())) {
                messages.add(ChatMessage.user(msg.content()));
            } else if ("assistant".equals(msg.role())) {
                messages.add(ChatMessage.assistant(msg.content()));
            }
        }
        messages.add(ChatMessage.user(message));

        int maxRounds = 40;
        boolean firstResponse = true;

        for (int round = 0; round < maxRounds; round++) {
            LlmRequest request = new LlmRequest(messages, toolDefs, 0.3, 8192);
            LlmResponse response = provider.complete(request).get(120, TimeUnit.SECONDS);

            if (response.finishReason() == LlmResponse.FinishReason.ERROR
                    || response.finishReason() == LlmResponse.FinishReason.RATE_LIMITED) {
                String errMsg = response.errorMessage() != null ? response.errorMessage() : "未知错误";
                if (chatPanel.isInStepMode()) {
                    SwingUtilities.invokeLater(() -> chatPanel.completeCurrentStep("请求失败: " + errMsg));
                } else {
                    SwingUtilities.invokeLater(() -> chatPanel.replaceLastAiMessage("请求失败: " + errMsg));
                }
                return;
            }

            if (response.hasToolCalls()) {
                if (firstResponse) {
                    SwingUtilities.invokeLater(() -> {
                        chatPanel.switchToStepMode();
                        chatPanel.addStep("Prompt", StepProgressPanel.StepType.PROMPT, message);
                        chatPanel.completeCurrentStep(message);
                    });
                    firstResponse = false;
                }

                // Complete any waiting "Thinking" step from previous round with actual content
                if (round > 0) {
                    String thinking = (response.content() != null && !response.content().isEmpty())
                            ? response.content() : "AI 已响应";
                    SwingUtilities.invokeLater(() -> chatPanel.completeCurrentStep(thinking));
                } else if (response.content() != null && !response.content().isEmpty()) {
                    // First round: AI returned thinking alongside tool calls
                    String thinking = response.content();
                    SwingUtilities.invokeLater(() -> {
                        chatPanel.addStep("Thinking", StepProgressPanel.StepType.THINKING, "");
                        chatPanel.completeCurrentStep(thinking);
                    });
                }

                messages.add(ChatMessage.assistantWithToolCalls(response.content(), response.toolCalls()));

                for (ToolCall tc : response.toolCalls()) {
                    String toolName = tc.toolName();
                    String truncArgs = tc.arguments().length() > 200
                            ? tc.arguments().substring(0, 200) + "..." : tc.arguments();
                    SwingUtilities.invokeLater(() ->
                            chatPanel.addStep(toolName, StepProgressPanel.StepType.TOOL_CALL, truncArgs));

                    String toolResult = registry.executeTool(tc.toolName(), tc.arguments());
                    String truncated = toolResult.length() > 16000
                            ? toolResult.substring(0, 16000) + "\n...[truncated]" : toolResult;
                    messages.add(ChatMessage.toolResult(tc.id(), truncated));

                    String stepDetail = truncated;
                    String reqRaw = null;
                    String respRaw = null;
                    if ("send_request".equals(tc.toolName())) {
                        var srt = (com.flechazo.apisentinel.ai.agent.tool.SendRequestTool) registry.getTool("send_request");
                        if (srt != null && !srt.getPayloadResults().isEmpty()) {
                            PayloadResult pr = srt.getPayloadResults().get(srt.getPayloadResults().size() - 1);
                            reqRaw = pr.sentRequest();
                            respRaw = pr.receivedResponse();
                        }
                        try {
                            var parsed = com.google.gson.JsonParser.parseString(toolResult).getAsJsonObject();
                            if (parsed.has("status_code")) {
                                int code = parsed.get("status_code").getAsInt();
                                long ms = parsed.has("response_time_ms") ? parsed.get("response_time_ms").getAsLong() : 0;
                                stepDetail = String.format("HTTP %d (%dms)\n\n```json\n%s\n```",
                                        code, ms, truncated.length() > 2000 ? truncated.substring(0, 2000) + "..." : truncated);
                            }
                        } catch (Exception ignored) {}
                    }
                    String finalDetail = stepDetail;
                    String finalReq = reqRaw;
                    String finalResp = respRaw;
                    SwingUtilities.invokeLater(() -> chatPanel.completeCurrentStep(finalDetail, finalReq, finalResp));
                }

                // Show a "thinking" spinner while waiting for the next AI response
                if (round + 1 < maxRounds) {
                    SwingUtilities.invokeLater(() ->
                            chatPanel.addStep("Thinking", StepProgressPanel.StepType.THINKING, "等待 AI 响应..."));
                }
            } else {
                // Complete any pending "Thinking" waiting step
                if (!firstResponse && round > 0) {
                    SwingUtilities.invokeLater(() -> chatPanel.completeCurrentStep());
                }
                String reply = response.content() != null ? response.content() : "(无响应内容)";
                if (chatPanel.isInStepMode()) {
                    SwingUtilities.invokeLater(() -> chatPanel.showFinalResponse(reply));
                } else {
                    SwingUtilities.invokeLater(() -> chatPanel.replaceToolProgressWithReply(reply));
                }
                pushSendRequestResultsToRepeater(registry);
                return;
            }
        }

        pushSendRequestResultsToRepeater(registry);
        chatPanel.setBusy(false);
        if (chatPanel.isInStepMode()) {
            SwingUtilities.invokeLater(() -> chatPanel.showFinalResponse("已达到工具调用上限。"));
        } else {
            SwingUtilities.invokeLater(() -> chatPanel.appendProgressNote("已达到工具调用上限。"));
        }
    }

    private void pushSendRequestResultsToRepeater(
            com.flechazo.apisentinel.ai.agent.tool.AgentToolRegistry registry) {
        var srt = (com.flechazo.apisentinel.ai.agent.tool.SendRequestTool) registry.getTool("send_request");
        if (srt == null) return;
        var results = srt.getPayloadResults();
        if (results.isEmpty()) return;

        RepeaterPanel repeaterPanel = view != null ? view.getRepeaterPanel() : null;
        if (repeaterPanel == null) return;

        for (PayloadResult pr : results) {
            repeaterPanel.addFollowUpPayloadResult(pr);
        }
    }

}
