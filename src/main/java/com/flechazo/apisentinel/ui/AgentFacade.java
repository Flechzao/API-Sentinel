package com.flechazo.apisentinel.ui;

import burp.api.montoya.MontoyaApi;
import com.flechazo.apisentinel.ai.agent.AgentLoop;
import com.flechazo.apisentinel.ai.pipeline.PipelineConfig;
import com.flechazo.apisentinel.ai.pipeline.PipelineResult;
import com.flechazo.apisentinel.ai.provider.LlmProvider;
import com.flechazo.apisentinel.ai.queue.AnalysisTaskQueue;
import com.flechazo.apisentinel.codeindex.CodeIndexService;
import com.flechazo.apisentinel.config.ConfigManager;
import com.flechazo.apisentinel.detection.OobService;
import com.flechazo.apisentinel.logging.LeveledLogger;
import com.flechazo.apisentinel.model.ApiEntry;
import com.flechazo.apisentinel.model.ApiEntryTableModel;

import javax.swing.SwingUtilities;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Agent (ReAct tool-calling loop) execution. Depends one-directionally on
 * PipelineFacade to reuse its completion handling — Agent mode produces the
 * same PipelineResult shape as Pipeline mode and should get identical
 * persistence/reporting/alerting, so there's no reason to duplicate
 * handlePipelineComplete/buildPipelineSummaryForChat here.
 */
class AgentFacade {

    private final MontoyaApi api;
    private final ConfigManager configManager;
    private final CodeIndexService codeIndexService;
    private final AnalysisTaskQueue analysisQueue;
    private final LeveledLogger logger;
    private final PipelineFacade pipelineFacade;
    private final OobService oobService;
    private final java.util.Set<AgentLoop> activeLoops = ConcurrentHashMap.newKeySet();
    /** UI bridge for ask_user / sandbox-confirm cards in the chat flow. */
    private com.flechazo.apisentinel.ai.agent.tool.UserInteractionBridge interactionBridge;
    private ApiEntryTableModel tableModel;

    private ApiSentinelTab view;
    private com.flechazo.apisentinel.ai.patterns.PatternStore patternStore;

    AgentFacade(MontoyaApi api, ConfigManager configManager, CodeIndexService codeIndexService,
                AnalysisTaskQueue analysisQueue, LeveledLogger logger, PipelineFacade pipelineFacade,
                OobService oobService) {
        this.api = api;
        this.configManager = configManager;
        this.codeIndexService = codeIndexService;
        this.analysisQueue = analysisQueue;
        this.logger = logger;
        this.pipelineFacade = pipelineFacade;
        this.oobService = oobService;
    }

    void setView(ApiSentinelTab view) { this.view = view; }

    void setInteractionBridge(com.flechazo.apisentinel.ai.agent.tool.UserInteractionBridge bridge) {
        this.interactionBridge = bridge;
    }

    void setTableModel(ApiEntryTableModel tableModel) { this.tableModel = tableModel; }

    /** Ask every in-flight Agent run to stop (chat stop button). Cancelled
     *  runs still complete normally — with a fallback verdict built from the
     *  evidence collected so far, so partial results are kept, not lost. */
    void cancelAll() {
        for (AgentLoop l : activeLoops) {
            try { l.cancel(); } catch (Exception ignored) {}
        }
    }

    void setPatternStore(com.flechazo.apisentinel.ai.patterns.PatternStore store) {
        this.patternStore = store;
    }

    void shutdown() {
        // Cancel BEFORE shutting the executors down: a graceful
        // executor.shutdown() would leave in-flight loops running on the
        // dying ClassLoader, where they soon hit NoClassDefFoundError and
        // die without settling their UI/persistence state (the "Agent
        // 启动中..." forever bug on extension reload). cancel() makes each
        // loop finish promptly with its evidence-fallback + final note.
        for (AgentLoop l : activeLoops) {
            try { l.cancel(); } catch (Exception ignored) {}
        }
        for (AgentLoop l : activeLoops) {
            try { l.shutdown(); } catch (Exception ignored) {}
        }
        // Bounded settle from THIS (unload) thread so each cancelled run can
        // land its final state (fallback verdict + "[用户中断]" chat note)
        // before the ClassLoader dies; hard-stop whatever survives.
        for (AgentLoop l : activeLoops) {
            try {
                if (!l.awaitSettled(5000)) l.shutdownNow();
            } catch (Exception ignored) {}
        }
        activeLoops.clear();
    }

    /** @param onDone called exactly once, on either completion or error — see
     *                PipelineFacade.executePipelineForEntry's javadoc. */
    void executeAgentForEntry(ApiEntry entry, LlmProvider provider, Runnable onDone) {
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

        AgentLoop agentLoop = new AgentLoop(provider, api, codeIndexService, pipelineConfig,
                appConfig.getCodeRepos(), logger, oobService, patternStore, interactionBridge);
        activeLoops.add(agentLoop);

        AiAnalysisPanel panel = view != null ? view.getAiAnalysisPanel() : null;
        AiChatPanel chatPanel = view != null ? view.getAiChatPanel() : null;
        final String entryPath = entry.getApiPath();

        var taskRecord = analysisQueue.addExternalRecord(entry.getApiPath(), "Agent");

        if (chatPanel != null) chatPanel.setAnalysisActive(true);
        if (tableModel != null) tableModel.markAnalyzing(entry.getApiPath());
        // Point the Repeater at this entry so live test-case/payload updates
        // render in real time (they're gated on isShowingEntry).
        if (view != null) {
            view.getRepeaterPanel().beginLiveTracking(
                    entry.getApiPath(), entry.getDomain(), entry.getLastUrl());
        }

        if (chatPanel != null) {
            // Do NOT clearHistoryForPath here — it wiped the user's prior
            // conversation for this endpoint the moment an analysis started, so
            // they lost their chat history. Preserve it; the analysis just appends
            // a marker and (below) renders its own progress in the step view.
            chatPanel.setContext(entry);
            chatPanel.appendProgressNoteForPath(entryPath, "🤖 开始 Agent 模式分析: "
                    + entry.getHttpMethod() + " " + entry.getApiPath());
            // Unified card flow: one-shot Agent analysis renders as step cards
            // (matching the interactive chat agent and Pipeline stages).
            chatPanel.switchToStepMode();
            // The conversation lives in the floating window now — surface it
            // so the step cards (and any sandbox confirm / ask_user card
            // waiting on the operator) are actually visible. Closing the
            // window again keeps the run going in the background.
            if (view != null) view.showChatWindow();
        }
        if (panel != null) {
            panel.resetPipelineProgress(true);
            panel.setAgentRunning(true);
        }

        final int[] currentIter = {0};
        final boolean[] firstTestCaseBatch = {true};
        // Guards: callbackFired — a lifecycle callback ran (so its cleanup
        // already happened); doneFired — onDone must run exactly once across
        // callbacks and the future's safety net.
        final java.util.concurrent.atomic.AtomicBoolean callbackFired =
                new java.util.concurrent.atomic.AtomicBoolean(false);
        final java.util.concurrent.atomic.AtomicBoolean doneFired =
                new java.util.concurrent.atomic.AtomicBoolean(false);
        final Runnable safeDone = () -> {
            if (doneFired.compareAndSet(false, true)) onDone.run();
        };

        java.util.concurrent.CompletableFuture<PipelineResult> loopFuture =
                agentLoop.execute(entry, new AgentLoop.AgentCallback() {
            @Override
            public void onAgentThinking(String thought) {
                logger.info("[Agent] 思考: %s", thought.length() > 100 ? thought.substring(0, 100) + "..." : thought);
                if (chatPanel != null) {
                    chatPanel.addAiMessageForPath(entryPath, "🧠 **Agent 思考：**\n\n" + thought);
                    chatPanel.addStep("Thinking", StepProgressPanel.StepType.THINKING, "");
                    chatPanel.completeCurrentStep(thought);
                }
                if (panel != null) {
                    panel.getTimelinePanel().addEvent(TimelineEvent.thinking(thought));
                }
            }

            @Override
            public void onToolCall(String toolName, String args) {
                logger.info("[Agent] 调用工具: %s", toolName);
                boolean isLlmCall = "analyze_traffic".equals(toolName) || "generate_payloads".equals(toolName);
                if (chatPanel != null) {
                    String displayArgs = args.length() > 200 ? args.substring(0, 200) + "..." : args;
                    chatPanel.appendProgressNoteForPath(entryPath,
                            "🔧 调用工具: " + toolName + (displayArgs.equals("{}") ? "" : " | 参数: " + displayArgs));
                    chatPanel.addStep(toolName, StepProgressPanel.StepType.TOOL_CALL, displayArgs);
                }
                if (panel != null) {
                    panel.setAgentProgress(currentIter[0], AgentLoop.MAX_ITERATIONS, toolName, "执行中...", false);
                    panel.getTimelinePanel().addEvent(TimelineEvent.toolCall(toolName, args, isLlmCall));
                }
            }

            @Override
            public void onToolResult(String toolName, String result) {
                logger.info("[Agent] 工具 %s 返回 %d 字符", toolName, result.length());
                if (chatPanel != null) {
                    String display = result.length() > 500 ? result.substring(0, 500) + "\n...[截断]" : result;
                    chatPanel.addAiMessageForPath(entryPath, "📋 **工具结果 [" + toolName + "]:**\n\n```json\n" + display + "\n```");
                    // Complete the step card opened in onToolCall with a fuller detail.
                    String stepDetail = result.length() > 2000 ? result.substring(0, 2000) + "\n...[截断]" : result;
                    // Lead send_request cards with an "HTTP <code> (<ms>)" metadata line so
                    // the collapsed summary shows the key outcome at a glance.
                    if ("send_request".equals(toolName)) {
                        try {
                            var parsed = com.google.gson.JsonParser.parseString(result).getAsJsonObject();
                            if (parsed.has("status_code")) {
                                int code = parsed.get("status_code").getAsInt();
                                long ms = parsed.has("response_time_ms") ? parsed.get("response_time_ms").getAsLong() : 0;
                                String body = stepDetail.length() > 1500 ? stepDetail.substring(0, 1500) + "..." : stepDetail;
                                stepDetail = String.format("HTTP %d (%dms)%n%s", code, ms, body);
                            }
                        } catch (Exception ignored) {}
                    }
                    chatPanel.completeCurrentStep(stepDetail);
                }

                if (panel != null) {
                    panel.setAgentProgress(currentIter[0], AgentLoop.MAX_ITERATIONS, toolName, "完成", true);
                    boolean anomaly = result != null && (result.contains("\"anomaly\":true") || result.contains("异常"));
                    boolean waf = result != null && (result.contains("waf") || result.contains("WAF") || result.contains("拦截"));
                    panel.getTimelinePanel().addEvent(TimelineEvent.toolResult(toolName, result, anomaly, waf));
                }
            }

            @Override
            public void onTestCasesGenerated(java.util.List<com.flechazo.apisentinel.testgen.model.TestCase> allCases) {
                if (view != null) {
                    boolean switchTab = firstTestCaseBatch[0];
                    firstTestCaseBatch[0] = false;
                    view.getRepeaterPanel().showLiveTestCases(entryPath, allCases);
                    if (switchTab) {
                        SwingUtilities.invokeLater(view::switchToRepeater);
                    }
                }
            }

            @Override
            public void onPayloadResultReady(com.flechazo.apisentinel.ai.pipeline.PayloadResult result, int resultIndex) {
                if (view != null) {
                    view.getRepeaterPanel().showLivePayloadResult(entryPath, result, resultIndex);
                }
            }

            @Override
            public void onAgentComplete(PipelineResult result) {
                callbackFired.set(true);
                agentLoop.shutdown();
                activeLoops.remove(agentLoop);
                if (chatPanel != null) chatPanel.setAnalysisActive(false);
                // Converge the step counter to N/N — trailing steps that never
                // got a completion event (e.g. calls queued after an accepted
                // submit_report) would otherwise spin forever ("34/44").
                if (chatPanel != null) chatPanel.finishSteps();
                if (tableModel != null) tableModel.clearAnalyzing(entry.getApiPath());
                boolean userCancelled = agentLoop.isCancelled();
                int findings = 0;
                if (result.verdict() != null) {
                    findings = result.verdict().confirmedVulns().size()
                             + result.verdict().suspectedVulns().size();
                }
                taskRecord.markCompleted(findings);

                if (panel != null) {
                    panel.setAgentRunning(false);
                    // Determinate terminal state right here — setAgentProgress
                    // leaves the bar INDETERMINATE (running look), and an
                    // indeterminate RoundedProgressBar paints color-only with
                    // no string. showFinalVerdict also sets a final state, but
                    // if anything ever prevents it from landing, this one
                    // guarantees the bar never sticks at color-only.
                    panel.finishAgentProgress();
                }

                // Load test cases and payload results into Repeater — applyAgentResult
                // does this atomically in a single EDT dispatch (setCurrentEntryPath +
                // loadTestCases + every showPayloadResult/addFollowUpPayloadResult used
                // to each queue their own separate invokeLater, which could be
                // interleaved with unrelated EDT events and drop later rows).
                boolean hasCases = result.testCases() != null && !result.testCases().isEmpty();
                boolean hasPayloads = result.payloadResults() != null && !result.payloadResults().isEmpty();
                if (view != null && (hasCases || hasPayloads)) {
                    // switchToRepeater() has no EDT guard of its own — it must run as the
                    // onApplied callback (already on the EDT) rather than synchronously
                    // here, since onAgentComplete itself runs on the Agent's background thread.
                    view.getRepeaterPanel().applyAgentResult(
                            entry.getApiPath(), entry.getDomain(), entry.getLastUrl(),
                            result.testCases(), result.payloadResults(),
                            view::switchToRepeater);
                }

                if (chatPanel != null) {
                    String risk = result.verdict() != null ? result.verdict().overallRisk() : "UNKNOWN";
                    String summary = pipelineFacade.buildSummaryForChat(entry, result, "Agent");
                    if (userCancelled) {
                        chatPanel.appendProgressNoteForPath(entryPath,
                                "⛔ 已中断（迭代 " + currentIter[0] + "）— 部分结果已保留，最终风险: " + risk);
                    } else {
                        chatPanel.appendProgressNoteForPath(entryPath, "✅ Agent 分析完成，最终风险: " + risk);
                    }
                    chatPanel.addAiMessageForPath(entryPath, summary);
                    // Final conclusion as an expanded Response card in the step view.
                    chatPanel.showFinalResponse(summary);
                }

                pipelineFacade.handlePipelineComplete(entry, result, panel, "AGENT");
                // Push timeline verdict event
                if (panel != null && result.verdict() != null) {
                    var v = result.verdict();
                    panel.getTimelinePanel().addEvent(TimelineEvent.verdict(
                            v.overallRisk(), v.confirmedVulns().size(),
                            v.suspectedVulns().size(),
                            v.rejectionReasons() != null ? v.rejectionReasons().size() : 0));
                    panel.getTimelinePanel().setTotalTokens(v.totalTokensUsed());
                }
                safeDone.run();
            }

            @Override
            public void onAgentError(String error) {
                callbackFired.set(true);
                agentLoop.shutdown();
                activeLoops.remove(agentLoop);
                if (chatPanel != null) chatPanel.setAnalysisActive(false);
                if (chatPanel != null) chatPanel.finishSteps();
                if (tableModel != null) tableModel.clearAnalyzing(entry.getApiPath());
                logger.error("[Agent] 错误: %s (%s)", error, entry.getApiPath());
                if (panel != null) {
                    panel.setAgentRunning(false);
                    // Settle the bar to a terminal "已终止" state — leaving it
                    // on "Agent 运行中" made a finished run look stuck.
                    panel.abortAgentProgress(error);
                }
                if (chatPanel != null) {
                    chatPanel.appendProgressNoteForPath(entryPath, "⚠️ Agent: " + error);
                }
                safeDone.run();
            }

            @Override
            public void onIterationComplete(int iteration, int maxIterations) {
                currentIter[0] = iteration;
                // Update progress bar first (lightweight)
                if (panel != null) {
                    panel.setAgentProgress(iteration, maxIterations, "", "迭代 " + iteration + " 完成", true);
                }
                // Then update chat (heavier, may queue on EDT)
                if (chatPanel != null) {
                    chatPanel.appendProgressNoteForPath(entryPath,
                            "--- 迭代 " + iteration + "/" + maxIterations + " 完成 ---");
                }
                if (panel != null) {
                    panel.getTimelinePanel().addEvent(TimelineEvent.iteration(iteration, maxIterations));
                }
            }
        });

        // Safety net: the loop catches Throwable itself and always settles via
        // a callback, so this only fires if something escaped anyway (e.g. a
        // callback itself threw mid-cleanup). Without it the panel would sit
        // on "Agent 启动中..." with agentRunning stuck true forever.
        loopFuture.exceptionally(err -> {
            logger.error("[Agent] 循环异常终止: %s", String.valueOf(err));
            try {
                if (!callbackFired.get()) {
                    // No lifecycle callback ran — do the error-path cleanup here.
                    agentLoop.shutdown();
                    activeLoops.remove(agentLoop);
                    if (chatPanel != null) chatPanel.setAnalysisActive(false);
                    if (chatPanel != null) chatPanel.finishSteps();
                    if (tableModel != null) tableModel.clearAnalyzing(entry.getApiPath());
                    if (panel != null) {
                        panel.setAgentRunning(false);
                        panel.abortAgentProgress("循环异常终止");
                    }
                    if (chatPanel != null) {
                        chatPanel.appendProgressNoteForPath(entryPath,
                                "⚠️ Agent 异常终止，已重置分析状态");
                    }
                    taskRecord.markFailed("循环异常终止");
                }
            } catch (Throwable ignored) {}
            safeDone.run();
            return null;
        });
    }
}
