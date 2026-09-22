package com.flechazo.apisentinel.ui;

import burp.api.montoya.MontoyaApi;
import com.flechazo.apisentinel.ai.agent.AgentLoop;
import com.flechazo.apisentinel.ai.pipeline.AnalysisConfig;
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
 * Agent (ReAct tool-calling loop) execution. Uses {@link AnalysisCompletionHandler}
 * for shared completion handling (persistence, reporting, alerting) — the same
 * handler Pipeline mode uses, so both engines get identical completion treatment
 * without depending on each other.
 */
class AgentFacade {

    private final MontoyaApi api;
    private final ConfigManager configManager;
    private final CodeIndexService codeIndexService;
    private final AnalysisTaskQueue analysisQueue;
    private final LeveledLogger logger;
    private final AnalysisCompletionHandler completionHandler;
    private final OobService oobService;
    private final java.util.Set<AgentLoop> activeLoops = ConcurrentHashMap.newKeySet();
    /** UI bridge for ask_user / sandbox-confirm cards in the chat flow. */
    private com.flechazo.apisentinel.ai.agent.tool.UserInteractionBridge interactionBridge;
    private ApiEntryTableModel tableModel;

    private ApiSentinelTab view;
    private com.flechazo.apisentinel.ai.patterns.PatternStore patternStore;
    /** F-1: Browser service for client-side security testing (null if disabled). */
    private com.flechazo.apisentinel.browser.BrowserService browserService;
    /** F-1: API repository for registering browser-discovered APIs. */
    private com.flechazo.apisentinel.repository.ApiRepository repository;
    /** Fast/cheap model name for plan generation + hypothesis generation. */
    private String fastModel;

    AgentFacade(MontoyaApi api, ConfigManager configManager, CodeIndexService codeIndexService,
                AnalysisTaskQueue analysisQueue, LeveledLogger logger,
                AnalysisCompletionHandler completionHandler,
                OobService oobService) {
        this.api = api;
        this.configManager = configManager;
        this.codeIndexService = codeIndexService;
        this.analysisQueue = analysisQueue;
        this.logger = logger;
        this.completionHandler = completionHandler;
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

    /** F-1: Set browser service for client-side security testing. */
    void setBrowserService(com.flechazo.apisentinel.browser.BrowserService browserService) {
        this.browserService = browserService;
    }

    /** F-1: Set API repository for registering browser-discovered APIs. */
    void setRepository(com.flechazo.apisentinel.repository.ApiRepository repository) {
        this.repository = repository;
    }

    /** Shared login-profile manager (also used by MCP) — enables browser_login. */
    private com.flechazo.apisentinel.config.LoginProfileManager loginProfileManager;
    void setLoginProfileManager(com.flechazo.apisentinel.config.LoginProfileManager m) {
        this.loginProfileManager = m;
    }

    /** Set the fast/cheap model name for plan generation + hypothesis generation. */
    void setFastModel(String model) {
        this.fastModel = model;
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

    /**
     * Multi-endpoint joint analysis: one Agent loop analyzes all entries together.
     */
    void executeAgentForEntries(java.util.List<ApiEntry> entries, LlmProvider provider, Runnable onDone) {
        if (entries == null || entries.isEmpty()) {
            if (onDone != null) onDone.run();
            return;
        }
        // Mark all entries as analyzing
        if (tableModel != null) {
            for (ApiEntry e : entries) {
                tableModel.markAnalyzing(e.getApiPath());
            }
        }
        // Store the multi-entries list for AgentLoop to use in multi-entry prompt
        this.pendingMultiEntries = entries;
        // Delegate to single-entry execution with the primary entry.
        // Wrap onDone to also clear analyzing state for non-primary entries
        // that the Agent didn't explicitly submit reports for.
        ApiEntry primary = entries.get(0);
        Runnable wrappedOnDone = () -> {
            // Clear "analyzing" for all non-primary entries — the Agent
            // only updated the primary via onAgentComplete. Others may
            // or may not have received a submit_report; either way they
            // shouldn't be stuck in "analyzing" forever.
            if (tableModel != null) {
                for (int i = 1; i < entries.size(); i++) {
                    String path = entries.get(i).getApiPath();
                    // Only clear if still in analyzing state (not already
                    // completed by a submit_report callback)
                    if (tableModel.isAnalyzing(path)) {
                        tableModel.clearAnalyzing(path);
                    }
                }
            }
            if (onDone != null) onDone.run();
        };
        executeAgentForEntry(primary, provider, wrappedOnDone);
    }

    /** Pending multi-entries list — set before calling executeAgentForEntry,
     *  consumed by the method to configure AgentLoop.setMultiEntries(). */
    private java.util.List<ApiEntry> pendingMultiEntries = java.util.List.of();

    /** @param onDone called exactly once, on either completion or error — see
     *                PipelineFacade.executePipelineForEntry's javadoc (same contract). */
    void executeAgentForEntry(ApiEntry entry, LlmProvider provider, Runnable onDone) {
        var appConfig = configManager.getConfig();
        boolean authTestEnabled = appConfig.isUnauthorizedDetectionEnabled();
        AnalysisConfig pipelineConfig = AnalysisConfig.forPipeline(appConfig, authTestEnabled);

        AgentLoop agentLoop = new AgentLoop(provider, api, codeIndexService, pipelineConfig,
                appConfig.getCodeRepos(), logger, oobService, patternStore, interactionBridge);
        // Pass fast model name for Plan-then-Execute + Hypothesis Generator.
        // Try the field first (set at init), then fall back to the settings panel
        // (in case the user updated it after AgentFacade was created).
        String effectiveFastModel = fastModel;
        if ((effectiveFastModel == null || effectiveFastModel.isBlank())
                && view != null && view.getAiSettingsPanel() != null) {
            effectiveFastModel = view.getAiSettingsPanel().getFastModel();
        }
        if (effectiveFastModel != null && !effectiveFastModel.isBlank()) {
            agentLoop.setFastModel(effectiveFastModel);
            logger.info("[Agent] Fast model '%s' 已启用 → Plan-then-Execute + 假设树激活",
                    effectiveFastModel);
        }
        // Pass disabled tools from config
        if (configManager.getConfig().getDisabledTools() != null
                && !configManager.getConfig().getDisabledTools().isEmpty()) {
            agentLoop.setDisabledTools(configManager.getConfig().getDisabledTools());
        }
        // Pass cascade hunting setting
        agentLoop.setCascadeEnabled(appConfig.isCascadeHuntEnabled());
        // F-1: Inject browser service and repository if enabled
        if (browserService != null) {
            agentLoop.setBrowserService(browserService);
        }
        if (repository != null) {
            agentLoop.setApiRepository(repository);
        }
        // Enable browser_login in the internal loop (shared profiles with MCP).
        agentLoop.setAppConfig(appConfig);
        if (loginProfileManager != null) {
            agentLoop.setLoginProfileManager(loginProfileManager);
        }
        // P1-6: propagate the raw-credentials opt-in from appConfig.
        agentLoop.setIncludeRawCredentials(
                configManager.getConfig().isIncludeRawCredentialsInLlm());
        // Reuse-window soft fold: same config as the pipeline — injects the
        // prior verdict into the initial user message so the agent
        // confirms/corrects rather than re-derives from scratch.
        agentLoop.setReuseWindowMinutes(appConfig.getAnalysisReuseWindowMinutes());
        // Multi-endpoint mode: if pendingMultiEntries is set, pass it to the
        // loop so it uses multi-entry prompt and sets allEntries on ToolContext.
        if (!pendingMultiEntries.isEmpty()) {
            agentLoop.setMultiEntries(pendingMultiEntries);
            pendingMultiEntries = java.util.List.of(); // consume
        }
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
        // Track last tool call args for unified card display in onToolResult
        final String[] lastToolName = {""};
        final String[] lastToolArgs = {""};
        final boolean[] firstTestCaseBatch = {true};
        // Agent mode rarely generates test cases (testCases is usually empty),
        // so onTestCasesGenerated — which auto-switches to the Repeater — never
        // fires. Without this, send_request results update the Repeater live
        // but the user stays on the 分析结果 tab and never sees them appear
        // in real time. Switch on the first payload result instead.
        final boolean[] firstPayloadResult = {true};
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
                logger.debug("[Agent] 思考: %s", thought.length() > 100 ? thought.substring(0, 100) + "..." : thought);
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
                logger.debug("[Agent] 调用工具: %s", toolName);
                lastToolName[0] = toolName;
                lastToolArgs[0] = args;
                boolean isLlmCall = "analyze_traffic".equals(toolName) || "generate_payloads".equals(toolName);
                if (chatPanel != null) {
                    String displayArgs = args.length() > 200 ? args.substring(0, 200) + "..." : args;
                    // Only add step card (not chat message) — the unified card
                    // will be shown in onToolResult when we have the result.
                    chatPanel.addStep(toolName, StepProgressPanel.StepType.TOOL_CALL, displayArgs);
                }
                if (panel != null) {
                    panel.setAgentProgress(currentIter[0], AgentLoop.MAX_ITERATIONS, toolName, "执行中...", false);
                    panel.getTimelinePanel().addEvent(TimelineEvent.toolCall(toolName, args, isLlmCall));
                }
            }

            @Override
            public void onToolResult(String toolName, String result) {
                logger.debug("[Agent] 工具 %s 返回 %d 字符", toolName, result.length());
                if (chatPanel != null) {
                    // Unified tool card: combines call + result in one message
                    String displayArgs = lastToolArgs[0].length() > 300
                            ? lastToolArgs[0].substring(0, 300) + "..." : lastToolArgs[0];
                    String display = result.length() > 2000
                            ? result.substring(0, 2000) + "\n...[截断，共 " + result.length() + " 字符]"
                            : result;
                    // Build a unified card message
                    StringBuilder card = new StringBuilder();
                    card.append("🔧 **").append(toolName).append("**\n");
                    if (!displayArgs.equals("{}") && !displayArgs.isEmpty()) {
                        card.append("- 参数: `").append(displayArgs).append("`\n");
                    }
                    card.append("- 结果:\n```json\n").append(display).append("\n```");
                    chatPanel.addAiMessageForPath(entryPath, card.toString());
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
                    // Auto-reveal the Repeater on the first send_request result
                    // so the user actually sees the live test list grow (Agent
                    // mode has no test-case batch to trigger switchToRepeater).
                    if (firstPayloadResult[0]) {
                        firstPayloadResult[0] = false;
                        SwingUtilities.invokeLater(view::switchToRepeater);
                    }
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
                    String summary = completionHandler.buildSummaryForChat(entry, result, "Agent");
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

                completionHandler.handleComplete(entry, result, panel, "AGENT");
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
                // Persist the failure into the queue record — without this, a
                // right-click "Agent analyze" whose loop dies mid-run leaves
                // its TaskRecord stuck IN_PROGRESS forever (the symmetric
                // onAgentComplete already calls markCompleted). The table
                // model refuses removeRecord(IN_PROGRESS), so the only other
                // way out was extension restart.
                taskRecord.markFailed(error);
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
                    // This is the mirror of onAgentError: persist failure into the
                    // queue record so the task doesn't sit IN_PROGRESS forever.
                    taskRecord.markFailed("循环异常终止");
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
                }
            } catch (Throwable ignored) {}
            safeDone.run();
            return null;
        });
    }
}
