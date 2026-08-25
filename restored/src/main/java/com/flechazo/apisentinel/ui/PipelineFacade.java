package com.flechazo.apisentinel.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import com.flechazo.apisentinel.ai.pipeline.AnalysisPipeline;
import com.flechazo.apisentinel.ai.pipeline.ConfirmedVuln;
import com.flechazo.apisentinel.ai.pipeline.FinalVerdict;
import com.flechazo.apisentinel.ai.pipeline.PayloadResult;
import com.flechazo.apisentinel.ai.pipeline.PipelineConfig;
import com.flechazo.apisentinel.ai.pipeline.PipelineResult;
import com.flechazo.apisentinel.ai.pipeline.SuspectedVuln;
import com.flechazo.apisentinel.ai.pipeline.VerdictValidator;
import com.flechazo.apisentinel.ai.pipeline.VulnEndpointAttributor;
import com.flechazo.apisentinel.ai.provider.LlmProvider;
import com.flechazo.apisentinel.ai.pipeline.PipelineReportWriter;
import com.flechazo.apisentinel.ai.rules.LearnedRuleEngine;
import com.flechazo.apisentinel.codeindex.CodeIndexService;
import com.flechazo.apisentinel.config.ConfigManager;
import com.flechazo.apisentinel.logging.LeveledLogger;
import com.flechazo.apisentinel.model.AnalysisRecord;
import com.flechazo.apisentinel.model.ApiEntry;
import com.flechazo.apisentinel.model.ApiEntryTableModel;
import com.flechazo.apisentinel.model.ApiStatus;
import com.flechazo.apisentinel.model.VulnType;
import com.flechazo.apisentinel.repository.ApiRepository;

import javax.swing.JTabbedPane;
import javax.swing.SwingUtilities;
import java.awt.Container;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Pipeline (6-stage deterministic) execution + shared completion handling
 * (persist AnalysisRecord, report to Burp Site Map, save a standalone report,
 * high-risk toast). AgentFacade also calls handlePipelineComplete/
 * buildPipelineSummaryForChat here since Agent mode produces the same
 * PipelineResult shape and should get identical completion treatment —
 * that's the one deliberate cross-facade dependency (Agent -> Pipeline,
 * one-directional, no cycle).
 *
 * Deliberately doesn't know about Agent mode or batch orchestration: the
 * Agent-mode routing decision lives in AiPresenter (the only place that
 * needs to know both PipelineFacade and AgentFacade exist), and batch
 * completion is reported back via the injected onDone callback rather than
 * this class reaching into BatchOrchestrator's state directly.
 */
/** Pipeline Facade——编排 Pipeline 分析的启动、进度回调、结果落盘和级联触发。 */
class PipelineFacade {

    private final MontoyaApi api;
    private final ConfigManager configManager;
    private final ApiEntryTableModel tableModel;
    private final com.flechazo.apisentinel.ai.queue.AnalysisTaskQueue analysisQueue;
    private final CodeIndexService codeIndexService;
    private final LeveledLogger logger;
    private final java.util.Set<AnalysisPipeline> activePipelines = ConcurrentHashMap.newKeySet();

    private ApiSentinelTab view;
    private LearnedRuleEngine learnedRuleEngine;
    private com.flechazo.apisentinel.mcp.McpTools mcpTools;
    /** EventBus for the cascade-hunting trigger; optional (null = no cascade). */
    private com.flechazo.apisentinel.event.EventBus eventBus;
    /** Success-pattern memory (P3); optional (null = patterns not recorded). */
    private com.flechazo.apisentinel.ai.patterns.PatternStore patternStore;
    /** Repository for cross-endpoint vuln attribution (null = attribution off).
     *  Cluster-hunting runs confirm vulns on sibling endpoints; without this
     *  every finding lands on the source row, which misrepresents the table. */
    private ApiRepository repository;

    PipelineFacade(MontoyaApi api, ConfigManager configManager, ApiEntryTableModel tableModel,
                   com.flechazo.apisentinel.ai.queue.AnalysisTaskQueue analysisQueue,
                   CodeIndexService codeIndexService, LeveledLogger logger) {
        this.api = api;
        this.configManager = configManager;
        this.tableModel = tableModel;
        this.analysisQueue = analysisQueue;
        this.codeIndexService = codeIndexService;
        this.logger = logger;
    }

    void setView(ApiSentinelTab view) { this.view = view; }

    /** Ask every in-flight Pipeline run to stop (chat stop button). Stopped
     *  runs report via onPipelineCancelled — no result, no error toast, run
     *  state cleanly released. */
    void cancelAll() {
        for (AnalysisPipeline p : activePipelines) {
            try { p.cancel(); } catch (Exception ignored) {}
        }
    }
    void setLearnedRuleEngine(LearnedRuleEngine engine) { this.learnedRuleEngine = engine; }
    void setMcpTools(com.flechazo.apisentinel.mcp.McpTools tools) { this.mcpTools = tools; }
    void setEventBus(com.flechazo.apisentinel.event.EventBus eventBus) { this.eventBus = eventBus; }
    void setPatternStore(com.flechazo.apisentinel.ai.patterns.PatternStore store) { this.patternStore = store; }
    void setRepository(ApiRepository repository) { this.repository = repository; }

    void shutdown() {
        // Cancel before executor shutdown (same rationale as AgentFacade):
        // a graceful shutdown() alone leaves in-flight pipelines running on
        // the dying ClassLoader, where they die without settling UI state.
        for (AnalysisPipeline p : activePipelines) {
            try { p.cancel(); } catch (Exception ignored) {}
        }
        for (AnalysisPipeline p : activePipelines) {
            try { p.shutdown(); } catch (Exception ignored) {}
        }
        activePipelines.clear();
    }

    /** @param onDone called exactly once, on either completion or error — the
     *                single-entry entry point passes a no-op, batch mode
     *                passes its progress/slot-release logic. */
    void executePipelineForEntry(ApiEntry entry, LlmProvider provider, Runnable onDone) {
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
        // Note: Pipeline creates an internal ExecutorService. We must shut it down
        // after execution completes (or fails) to avoid thread leaks.
        AnalysisPipeline pipeline = new AnalysisPipeline(
                provider, api, codeIndexService, pipelineConfig,
                configManager.getConfig().getCodeRepos(), logger);
        // Multi-model tiering: route Stage-1 triage to the cheap model if set.
        if (view != null && view.getAiSettingsPanel() != null) {
            pipeline.setFastModel(view.getAiSettingsPanel().getFastModel());
        }
        // Cross-run reuse window for injecting prior verdicts as context.
        pipeline.setReuseWindowMinutes(appConfig.getAnalysisReuseWindowMinutes());
        activePipelines.add(pipeline);

        AiAnalysisPanel panel = view != null ? view.getAiAnalysisPanel() : null;
        AiChatPanel chatPanel = view != null ? view.getAiChatPanel() : null;
        final String entryPath = entry.getApiPath(); // capture for path-bound messages

        var taskRecord = analysisQueue.addExternalRecord(entry.getApiPath(), "Pipeline");

        if (chatPanel != null) chatPanel.setAnalysisActive(true);
        tableModel.markAnalyzing(entry.getApiPath());
        // Point the Repeater at this entry so live test-case/payload updates
        // render in real time (they're gated on isShowingEntry).
        if (view != null) {
            view.getRepeaterPanel().beginLiveTracking(
                    entry.getApiPath(), entry.getDomain(), entry.getLastUrl());
        }

        if (chatPanel != null) {
            chatPanel.setContextAsync(entry);
            chatPanel.appendProgressNoteForPath(entryPath, "🚀 开始 Pipeline 分析: "
                    + entry.getHttpMethod() + " " + entry.getApiPath());
        }

        pipeline.execute(entry, new AnalysisPipeline.PipelineCallback() {
            @Override public void onStageStart(int stage, String description) {
                logger.info("[Pipeline] 阶段%d开始: %s (%s)", stage, description, entry.getApiPath());
                if (panel != null) {
                    panel.setPipelineProgress(stage, description, false);
                    panel.getTimelinePanel().addEvent(TimelineEvent.stage(stage, description, true));
                }
                if (chatPanel != null) {
                    chatPanel.appendProgressNoteForPath(entryPath, "▶ [阶段" + stage + "/6] " + description);
                    // Unified card flow: Pipeline stages appear as step cards too,
                    // matching the Agent mode step view. Switch to the step view on
                    // the first stage so the cards are actually visible.
                    if (stage == 1) chatPanel.switchToStepMode();
                    chatPanel.addStep(pipelineStageName(stage),
                            StepProgressPanel.StepType.TOOL_CALL, description);
                }
            }
            @Override public void onStageComplete(int stage, String summary) {
                logger.info("[Pipeline] 阶段%d完成: %s (%s)", stage, summary, entry.getApiPath());
                if (panel != null) {
                    panel.setPipelineProgress(stage, summary, true);
                    panel.getTimelinePanel().addEvent(TimelineEvent.stage(stage, summary, false));
                }
                if (chatPanel != null) {
                    String stageName = pipelineStageName(stage);
                    chatPanel.addAiMessageForPath(entryPath, "【阶段" + stage + "/6 – " + stageName + " 完成】\n\n" + summary);
                    chatPanel.completeCurrentStep(summary);
                }
            }
            @Override public void onTrafficDataIdentified(String method, String url, int statusCode,
                                                           String requestSnippet, String responseSnippet) {
                if (chatPanel != null) {
                    StringBuilder sb = new StringBuilder();
                    sb.append("📋 **正在分析的流量数据：**\n");
                    sb.append("请求: ").append(method).append(" ").append(url).append("\n");
                    sb.append("响应状态码: ").append(statusCode).append("\n\n");
                    sb.append("请求摘要:\n```\n").append(requestSnippet).append("\n```\n\n");
                    sb.append("响应摘要:\n```\n").append(responseSnippet).append("\n```");
                    chatPanel.addAiMessageForPath(entryPath, sb.toString());
                }
            }
            @Override public void onAiThinkingOutput(int stage, String stageName, String rawAiText) {
                if (chatPanel != null) {
                    chatPanel.addAiMessageForPath(entryPath, "🧠 【阶段" + stage + " – " + stageName + " — AI思考过程】\n\n" + rawAiText);
                }
            }
            @Override public void onTestCasesGenerated(List<com.flechazo.apisentinel.testgen.model.TestCase> testCases) {
                if (view != null) {
                    SwingUtilities.invokeLater(() -> {
                        // Entry-switch guard: the Repeater panel is shared across all
                        // entries, and BatchOrchestrator allows up to 2 concurrent
                        // Pipeline/Agent runs — without this check, an entry the user
                        // isn't currently viewing would reset/overwrite whatever entry
                        // IS currently shown. Checked here (inside the invokeLater,
                        // right before mutating) rather than by the caller, since the
                        // caller runs on the pipeline's background thread and the
                        // selection could change during the time this Runnable sits
                        // queued on the EDT.
                        RepeaterPanel rp = view.getRepeaterPanel();
                        if (!rp.isShowingEntry(entry.getApiPath())) return;
                        rp.setCurrentHost(entry.getDomain());
                        rp.doLoadTestCases(testCases);
                        view.switchToRepeater();
                    });
                }
            }
            @Override public void onPayloadResult(int index, PayloadResult payloadResult) {
                if (view != null) {
                    SwingUtilities.invokeLater(() -> {
                        RepeaterPanel rp = view.getRepeaterPanel();
                        if (!rp.isShowingEntry(entry.getApiPath())) return;
                        rp.doShowPayloadResult(
                                index,
                                payloadResult.sentRequest(),
                                payloadResult.receivedResponse(),
                                payloadResult.statusCode(),
                                payloadResult.responseTimeMs(),
                                payloadResult.anomalyDetected(),
                                payloadResult.wafVendor(),
                                payloadResult.wafScore());
                    });
                }
            }
            @Override public void onAuthTestComplete(com.flechazo.apisentinel.auth.AuthTestResult result) {
                if (view != null && result.rounds() != null && !result.rounds().isEmpty()) {
                    SwingUtilities.invokeLater(() -> {
                        if (!view.getRepeaterPanel().isShowingEntry(entry.getApiPath())) return;
                        view.getRepeaterPanel().showAuthTestRounds(result);
                    });
                }
            }
            @Override public void onPayloadExecuted(int index, int total, String payload, int statusCode) {
                if (chatPanel != null) {
                    String truncPayload = payload != null && payload.length() > 60
                            ? payload.substring(0, 60) + "..." : payload;
                    chatPanel.appendProgressNoteForPath(entryPath, String.format(
                            "   Payload %d/%d: %s → HTTP %d", index, total, truncPayload, statusCode));
                }
            }
            @Override public void onPipelineComplete(PipelineResult result) {
                pipeline.shutdown();
                activePipelines.remove(pipeline);
                if (chatPanel != null) chatPanel.setAnalysisActive(false);
                if (chatPanel != null) chatPanel.finishSteps();
                tableModel.clearAnalyzing(entry.getApiPath());
                int findings = result.verdict().confirmedVulns().size()
                        + result.verdict().suspectedVulns().size();
                taskRecord.markCompleted(findings);
                if (chatPanel != null) {
                    chatPanel.appendProgressNoteForPath(entryPath, "✅ Pipeline 分析完成，最终风险: " + result.verdict().overallRisk());
                    chatPanel.addAiMessageForPath(entryPath, buildPipelineSummaryForChat(entry, result));
                }
                handlePipelineComplete(entry, result, panel, "PIPELINE");
                // Push timeline verdict event
                if (panel != null && result.verdict() != null) {
                    var v = result.verdict();
                    panel.getTimelinePanel().addEvent(TimelineEvent.verdict(
                            v.overallRisk(), v.confirmedVulns().size(),
                            v.suspectedVulns().size(),
                            v.rejectionReasons() != null ? v.rejectionReasons().size() : 0));
                    panel.getTimelinePanel().setTotalTokens(v.totalTokensUsed());
                }
                onDone.run();
            }
            @Override public void onPipelineError(String error) {
                pipeline.shutdown();
                activePipelines.remove(pipeline);
                if (chatPanel != null) chatPanel.setAnalysisActive(false);
                if (chatPanel != null) chatPanel.finishSteps();
                tableModel.clearAnalyzing(entry.getApiPath());
                taskRecord.markFailed(error);
                logger.error("[Pipeline] 错误: %s (%s)", error, entry.getApiPath());
                if (panel != null) panel.showPipelineError(error);
                if (chatPanel != null) chatPanel.appendProgressNoteForPath(entryPath, "❌ Pipeline 分析失败: " + error);
                if (view != null) {
                    SwingUtilities.invokeLater(() ->
                        ToastNotification.show(view, "分析失败: " + error,
                                ToastNotification.ToastType.WARNING, 5000));
                }
                onDone.run();
            }
            @Override public void onPipelineCancelled() {
                pipeline.shutdown();
                activePipelines.remove(pipeline);
                if (chatPanel != null) chatPanel.setAnalysisActive(false);
                if (chatPanel != null) chatPanel.finishSteps();
                tableModel.clearAnalyzing(entry.getApiPath());
                taskRecord.markFailed("用户中断");
                logger.info("[Pipeline] 用户中断 (%s)", entry.getApiPath());
                if (chatPanel != null) {
                    chatPanel.appendProgressNoteForPath(entryPath, "⛔ 已中断 Pipeline 分析（剩余阶段已跳过）");
                }
                if (panel != null) {
                    SwingUtilities.invokeLater(() ->
                            panel.setPipelineProgress(0, "已中断（用户请求）", true));
                }
                onDone.run();
            }
        });
    }

    /**
     * Build a chat-friendly summary of the final pipeline verdict, stored in
     * AiChatPanel's conversation history so the user can ask follow-up questions.
     * Also called by AgentFacade, since Agent mode produces the same PipelineResult.
     */
    String buildPipelineSummaryForChat(ApiEntry entry, PipelineResult result) {
        return buildSummaryForChat(entry, result, "Pipeline");
    }

    String buildSummaryForChat(ApiEntry entry, PipelineResult result, String modeLabel) {
        var verdict = result.verdict();
        StringBuilder sb = new StringBuilder();
        sb.append("**").append(modeLabel).append(" 分析完成** — ").append(entry.getHttpMethod()).append(" ").append(entry.getApiPath()).append("\n\n");
        sb.append("总体风险: ").append(verdict.overallRisk()).append("\n\n");

        if (!verdict.confirmedVulns().isEmpty()) {
            sb.append("已确认漏洞 (").append(verdict.confirmedVulns().size()).append("):\n");
            for (var cv : verdict.confirmedVulns()) {
                sb.append("- [").append(cv.type()).append("] ").append(cv.title())
                        .append("\n  证据: ").append(cv.evidence()).append("\n");
            }
            sb.append("\n");
        }
        if (!verdict.suspectedVulns().isEmpty()) {
            sb.append("疑似漏洞 (").append(verdict.suspectedVulns().size()).append("):\n");
            for (var sv : verdict.suspectedVulns()) {
                sb.append("- [").append(sv.type()).append("] ").append(sv.title())
                        .append("\n  原因: ").append(sv.reason()).append("\n");
            }
            sb.append("\n");
        }
        var trafficFindings = result.trafficAnalysis() != null ? result.trafficAnalysis().findings() : null;
        if (trafficFindings != null && !trafficFindings.isEmpty()) {
            sb.append("阶段1初步评估 (流量分析, 共 ").append(trafficFindings.size()).append(" 项, 待Payload验证):\n");
            for (var f : trafficFindings) {
                sb.append("- [").append(f.risk()).append("][").append(f.type()).append("] ").append(f.title());
                if (f.evidence() != null && !f.evidence().isEmpty()) {
                    sb.append("\n  证据: ").append(f.evidence());
                }
                sb.append("\n");
            }
            sb.append("\n");
        }
        if (verdict.summary() != null && !verdict.summary().isEmpty()) {
            sb.append("摘要: ").append(verdict.summary()).append("\n\n");
        }
        if (verdict.recommendations() != null && !verdict.recommendations().isEmpty()) {
            sb.append("修复建议: ").append(verdict.recommendations()).append("\n\n");
        }
        sb.append("你可以针对以上结果继续追问，例如“这个漏洞怎么利用”或“给出绕过方案”。");
        return sb.toString();
    }

    /** Also called by AgentFacade — Agent mode produces the same PipelineResult
     *  shape and should get identical persistence/reporting/alerting.
     *  @param mode "PIPELINE" or "AGENT" — stored on the AnalysisRecord and
     *              shown in the status label, so Agent runs don't get
     *              mislabeled as "Pipeline 完成" in the UI/history dropdown. */
    void handlePipelineComplete(ApiEntry entry, PipelineResult result, AiAnalysisPanel panel, String mode) {
        logger.info("[%s] 完成: %s -> %s", mode, entry.getApiPath(), result.verdict().overallRisk());

        AnalysisRecord record = new AnalysisRecord(mode, result.trafficAnalysis());
        record = record.withTestCases(result.testCases());
        record = record.withPipelineResult(result);
        // Persist the call-chain timeline so the 调用链 view can be re-rendered
        // when this record is viewed later (it's otherwise ephemeral).
        if (panel != null && panel.getTimelinePanel() != null) {
            record = record.withTimeline(panel.getTimelinePanel().getEvents());
        }
        entry.addAnalysisRecord(record);
        tableModel.markRepositoryDirty();

        // Risk and findings are shown in dedicated table columns via
        // getDisplayRisk()/getDisplayFindings() (correctly derived from this
        // very record), but entry.status itself — the "状态" column, and what
        // every export (CSV/Markdown/完整报告) reads — was never updated here.
        // A confirmed-vuln run could sit at "未测试"/"接口测试中" forever,
        // since only human actions (标记为安全/标记漏洞) or the unrelated
        // UnauthorizedDetector ever touched entry.status before this.
        // Everything from here to the report saves is a chain of independent
        // sinks. EACH is isolated in its own try/catch so one failure (e.g. a
        // mid-unload RejectedExecutionException, an interrupted write, a
        // listener throwing) can never abort the completion flow before the
        // verdict/progress/report UI settles — that failure mode left panels
        // stuck, progress bars color-only, and report buttons missing.
        try {
            updateEntryStatusFromVerdict(entry, result.verdict());
        } catch (Throwable t) {
            logger.warn("[完成流程] 状态列更新失败: %s", t.getMessage());
        }

        try {
            // Cluster-hunting runs confirm vulns on SIBLING endpoints — sync
            // each of those to its own table row so the vuln lands on the
            // endpoint it was found on. The source entry keeps the full
            // verdict/report (the run's unit of analysis stays intact).
            attributeCrossEndpointVulns(entry, result.verdict());
        } catch (Throwable t) {
            logger.warn("[完成流程] 跨端点归因失败（不影响结果展示）: %s", t.getMessage());
        }

        try {
            // Cascade-hunting trigger (P2): VERIFIED confirmed vulns only —
            // suspected-only results must never cascade. AgentController
            // (auto-pilot) subscribes and queues the sibling endpoints.
            if (eventBus != null && result.verdict() != null
                    && result.verdict().confirmedVulns() != null
                    && !result.verdict().confirmedVulns().isEmpty()) {
                eventBus.publish(new com.flechazo.apisentinel.event.ClusterHuntTriggerEvent(
                        entry, entry.getHttpMethod(), result.verdict()));
            }
        } catch (Throwable t) {
            logger.warn("[完成流程] 级联事件发布失败: %s", t.getMessage());
        }

        try {
            // Push MCP event for external clients
            if (mcpTools != null && result.verdict() != null) {
                var v = result.verdict();
                mcpTools.pushEvent(com.flechazo.apisentinel.mcp.McpTools.McpEvent.analysisComplete(
                        entry.getApiPath(), v.overallRisk(),
                        v.confirmedVulns() != null ? v.confirmedVulns().size() : 0,
                        v.suspectedVulns() != null ? v.suspectedVulns().size() : 0));
                if ("HIGH".equals(v.overallRisk()) && v.confirmedVulns() != null && !v.confirmedVulns().isEmpty()) {
                    mcpTools.pushEvent(com.flechazo.apisentinel.mcp.McpTools.McpEvent.highRiskFound(
                            entry.getApiPath(), v.confirmedVulns().get(0).title()));
                }
            }
        } catch (Throwable t) {
            logger.warn("[完成流程] MCP 事件推送失败: %s", t.getMessage());
        }

        try {
            tableModel.refreshFromRepository();
        } catch (Throwable t) {
            logger.warn("[完成流程] 表格刷新失败: %s", t.getMessage());
        }

        try {
            if (view != null) {
                panel.showFinalVerdict(result.verdict(), result.trafficAnalysis(), mode, result.payloadResults());
                panel.refreshHistoryForEntry(entry);
                // Neither Pipeline nor Agent mode ever wrote the model label back
                // after resetPipelineProgress() cleared it to "Model: --" at the
                // start of the run — reuse the same source onProviderChanged uses.
                String model = view.getAiSettingsPanel().getModel();
                if (model != null && !model.isEmpty()) panel.setCurrentModel(model);
            }
        } catch (Throwable t) {
            logger.warn("[完成流程] 结论上屏失败: %s", t.getMessage());
        }

        try {
            showHighRiskAlert(view, entry, result.verdict().overallRisk());
        } catch (Throwable t) {
            logger.warn("[完成流程] 高危提醒失败: %s", t.getMessage());
        }

        // Report findings to Burp's Target → Site Map → Issues
        reportToSiteMap(entry, result);

        // Auto-send vuln evidence requests to Burp's native Organizer
        sendVulnsToOrganizer(entry, result);

        if (learnedRuleEngine != null && result.trafficAnalysis() != null
                && result.trafficAnalysis().isSuccess()) {
            learnedRuleEngine.learnFromAnalysis(entry.getApiPath(), result.trafficAnalysis());
        }

        // Success-pattern memory (P3): record VERIFIED confirms only — this is
        // the single completion sink for both Pipeline and Agent modes, so
        // every confirmed vuln anywhere feeds the store exactly once.
        if (patternStore != null && result.verdict() != null) {
            patternStore.recordConfirmations(entry, result.verdict());
        }

        // Save independent pipeline report to ~/.api-sentinel/reports/
        savePipelineReport(entry, result);
        saveHtmlReport(entry, result, panel);
    }

    /**
     * Advances entry.status based on what this run actually found.
     * A confirmed vuln is real, evidence-backed proof — it always wins, even
     * over a prior human "标记为安全"/"待评估" call, since the security state
     * can genuinely change between two analysis runs. A weaker signal
     * (suspected-only, or nothing found) only advances the status while it's
     * still at one of the "not meaningfully tested yet" states — it must
     * never downgrade a status a human already set deliberately.
     */
    private void updateEntryStatusFromVerdict(ApiEntry entry, FinalVerdict verdict) {
        if (verdict == null) return;
        List<ConfirmedVuln> own = ownConfirmedVulns(entry, verdict);
        if (!own.isEmpty()) {
            ConfirmedVuln first = own.get(0);
            entry.updateStatus(ApiStatus.VULNERABLE, inferVulnType(own), first.title());
            return;
        }
        ApiStatus current = entry.getStatus();
        if (current != ApiStatus.UNTESTED && current != ApiStatus.UNDER_TEST) {
            return; // don't clobber a human's own PASSED/PENDING_REVIEW/VULNERABLE call
        }
        int crossCount = (verdict.confirmedVulns() != null ? verdict.confirmedVulns().size() : 0) - own.size();
        boolean ownSuspected = verdict.suspectedVulns() != null && !verdict.suspectedVulns().isEmpty()
                && verdict.suspectedVulns().stream().anyMatch(s ->
                        !VulnEndpointAttributor.isCrossEndpointLike(entry.getApiPath(),
                                VulnEndpointAttributor.extractEndpoint(s.verifyCommand(), s.title())));
        if (ownSuspected) {
            entry.updateStatus(ApiStatus.PENDING_REVIEW, null, "AI 分析发现疑似漏洞，待人工确认");
        } else if (crossCount > 0) {
            entry.updateStatus(ApiStatus.PASSED, null,
                    "本端点未发现问题；" + crossCount + " 个确认漏洞位于其他端点，已同步到对应接口行");
        } else {
            entry.updateStatus(ApiStatus.PASSED, null, "AI 分析未发现漏洞");
        }
    }

    /** Confirmed vulns of this verdict that belong to the source endpoint
     *  itself (endpoint unresolved, or equal to the source path). */
    private List<ConfirmedVuln> ownConfirmedVulns(ApiEntry entry, FinalVerdict verdict) {
        java.util.List<ConfirmedVuln> own = new java.util.ArrayList<>();
        if (verdict.confirmedVulns() == null) return own;
        for (ConfirmedVuln v : verdict.confirmedVulns()) {
            String endpoint = VulnEndpointAttributor.extractEndpoint(v);
            if (endpoint == null || endpoint.equalsIgnoreCase(entry.getApiPath())) {
                own.add(v);
            }
        }
        return own;
    }

    /** Syncs cross-endpoint confirmed vulns onto their own table rows:
     *  creates the row when the endpoint isn't tracked yet, then marks it
     *  VULNERABLE via repository.updateStatus so change listeners (KPI bar)
     *  fire. Suspected findings are deliberately NOT synced — table rows
     *  only carry VERIFIED facts (same red line as cascade triggering). */
    private void attributeCrossEndpointVulns(ApiEntry entry, FinalVerdict verdict) {
        if (repository == null || verdict == null || verdict.confirmedVulns() == null) return;
        for (ConfirmedVuln v : verdict.confirmedVulns()) {
            String endpoint = VulnEndpointAttributor.extractEndpoint(v);
            if (endpoint == null || endpoint.equalsIgnoreCase(entry.getApiPath())) continue;
            if (repository.findByPath(endpoint).isEmpty()) {
                ApiEntry created = new ApiEntry(
                        VulnEndpointAttributor.extractMethod(v.verifyCommand(), "GET"), endpoint);
                created.setDomain(entry.getDomain());
                repository.add(created);
            }
            repository.updateStatus(endpoint, ApiStatus.VULNERABLE,
                    inferVulnType(List.of(v)),
                    v.title() + "（由 " + entry.getApiPath() + " 的分析发现）");
        }
    }

    /** Best-effort mapping from a confirmed vuln's free-text type to the
     *  fixed VulnType enum (used for highlight-color purposes elsewhere) —
     *  falls back to GENERIC for types outside the 4 specific categories. */
    private VulnType inferVulnType(List<ConfirmedVuln> confirmedVulns) {
        for (ConfirmedVuln cv : confirmedVulns) {
            String t = cv.type() != null ? cv.type() : "";
            if (t.contains("水平") && t.contains("越权")) return VulnType.HORIZONTAL_PRIV_ESC;
            if (t.contains("垂直") && t.contains("越权")) return VulnType.VERTICAL_PRIV_ESC;
            if (t.contains("越权") || t.contains("未授权")) return VulnType.UNAUTHORIZED;
            if (t.contains("敏感信息") || t.contains("信息泄露")) return VulnType.SENSITIVE_INFO;
        }
        return VulnType.GENERIC;
    }

    /**
     * Save a self-contained JSON report for this pipeline run.
     * Reports include full 6-stage data + payload execution results.
     */
    private void savePipelineReport(ApiEntry entry, PipelineResult result) {
        try {
            PipelineReportWriter reportWriter = new PipelineReportWriter(logger);
            java.nio.file.Path reportPath = reportWriter.saveReport(
                    entry, result, result.trafficStats());
            if (reportPath != null) {
                logger.info("[Pipeline] 分析报告已保存: %s", reportPath);
                if (view != null) {
                    AiChatPanel chatPanel = view.getAiChatPanel();
                    if (chatPanel != null) {
                        chatPanel.appendProgressNote(
                                "📄 分析报告已保存: " + reportPath.getFileName());
                    }
                    AiAnalysisPanel panel = view.getAiAnalysisPanel();
                    if (panel != null) {
                        final java.nio.file.Path jp = reportPath;
                        SwingUtilities.invokeLater(() -> panel.setJsonReportPath(jp));
                    }
                }
            }
        } catch (Exception e) {
            logger.error("[Pipeline] 保存分析报告失败: %s", e.getMessage());
        }
    }

    /**
     * Save a standalone, shareable HTML report — only when this run confirmed
     * or suspected at least one vuln (HtmlReportWriter.saveReport returns null
     * otherwise), unlike the JSON report above which is saved unconditionally.
     */
    private void saveHtmlReport(ApiEntry entry, PipelineResult result, AiAnalysisPanel panel) {
        try {
            com.flechazo.apisentinel.ai.pipeline.HtmlReportWriter htmlWriter =
                    new com.flechazo.apisentinel.ai.pipeline.HtmlReportWriter(logger);
            java.nio.file.Path htmlPath = htmlWriter.saveReport(entry, result);
            if (htmlPath != null) {
                logger.info("[Pipeline] HTML 报告已保存: %s", htmlPath);
                if (view != null) {
                    AiChatPanel chatPanel = view.getAiChatPanel();
                    if (chatPanel != null) {
                        chatPanel.appendProgressNote(
                                "📄 HTML 报告已保存: " + htmlPath.getFileName());
                    }
                }
                if (panel != null) {
                    SwingUtilities.invokeLater(() -> panel.setReportPath(htmlPath));
                }
            } else {
                // Not an error: the HTML report is findings-only. Log it so a
                // "查看报告按钮不见了" report can be triaged — if the verdict
                // confirmed/suspected nothing, no HTML (and no button) is the
                // designed outcome; the JSON 完整日志 button still shows.
                logger.info("[Pipeline] 本次无确认/疑似漏洞，未生成 HTML 报告（查看报告按钮不出现属正常）");
            }
        } catch (Exception e) {
            logger.error("[Pipeline] 保存 HTML 报告失败: %s", e.getMessage());
        }
    }

    /**
     * Montoya API has no method to drive Burp's own embedded browser (no
     * browser()-shaped interface exists anywhere in it) — the only portable
     * way to open a local file is the standard java.awt.Desktop API, which
     * opens whatever the OS's default browser is. Burp itself is a full
     * Swing desktop app, so java.desktop is guaranteed present in its JVM;
     * the only real failure mode is a headless/exotic Linux setup where
     * Desktop.isDesktopSupported() is false, handled by just logging instead
     * of throwing — a missing auto-open is not worth failing the whole
     * analysis-completion flow over.
     */


    /**
     * Report confirmed/suspected vulnerabilities to Burp's Site Map as AuditIssue entries,
     * making API-Sentinel findings visible in the Target → Issues panel alongside native Scanner results.
     */
    private void reportToSiteMap(ApiEntry entry, PipelineResult result) {
        try {
            var verdict = result.verdict();
            if (verdict.confirmedVulns().isEmpty() && verdict.suspectedVulns().isEmpty()) return;

            String baseUrl = entry.getLastUrl();
            if (baseUrl == null || baseUrl.isEmpty()) {
                String scheme = "https";
                String host = entry.getDomain().isEmpty() ? "unknown" : entry.getDomain();
                baseUrl = scheme + "://" + host + entry.getApiPath();
            }

            for (ConfirmedVuln cv : verdict.confirmedVulns()) {
                // Attach the real request/response that got this vuln
                // confirmed, if we can find it — Burp's native Issue detail
                // view renders it inline, so a reviewer doesn't need this
                // extension's own UI open to see the actual evidence.
                PayloadResult evidence = VerdictValidator.findPayloadResult(result.payloadResults(), cv.payloadUsed());
                HttpRequestResponse[] requestResponses = toRequestResponses(entry, evidence);
                AuditIssue issue = AuditIssue.auditIssue(
                        "[API-Sentinel] " + cv.title(),
                        buildIssueDetail(cv),
                        cv.verifyCommand() != null ? cv.verifyCommand() : "",
                        baseUrl,
                        AuditIssueSeverity.HIGH,
                        AuditIssueConfidence.FIRM,
                        "API Sentinel Pipeline 自动化分析确认的漏洞。类型: " + cv.type(),
                        verdict.recommendations() != null ? verdict.recommendations() : "",
                        AuditIssueSeverity.HIGH,
                        requestResponses
                );
                api.siteMap().add(issue);
                logger.info("[SiteMap] 上报确认漏洞: %s → %s", entry.getApiPath(), cv.title());
            }

            for (SuspectedVuln sv : verdict.suspectedVulns()) {
                AuditIssueSeverity severity = "HIGH".equals(verdict.overallRisk())
                        ? AuditIssueSeverity.MEDIUM : AuditIssueSeverity.LOW;
                AuditIssue issue = AuditIssue.auditIssue(
                        "[API-Sentinel] " + sv.title(),
                        "<b>疑似原因:</b> " + escapeHtml(sv.reason())
                                + "<br><br><b>类型:</b> " + escapeHtml(sv.type())
                                + "<br><b>验证命令:</b> <code>" + escapeHtml(sv.verifyCommand()) + "</code>",
                        sv.verifyCommand() != null ? sv.verifyCommand() : "",
                        baseUrl,
                        severity,
                        AuditIssueConfidence.TENTATIVE,
                        "API Sentinel Pipeline 分析识别的疑似漏洞，需要进一步手动验证。",
                        verdict.recommendations() != null ? verdict.recommendations() : "",
                        severity
                );
                api.siteMap().add(issue);
                logger.info("[SiteMap] 上报疑似漏洞: %s → %s", entry.getApiPath(), sv.title());
            }
        } catch (Exception e) {
            logger.debug("上报 SiteMap AuditIssue 失败: %s", e.getMessage());
        }
    }

    /**
     * Auto-send the evidence request/response of confirmed vulns to Burp's native
     * Organizer so the user can review them inside Burp's own workflow. Gated by
     * the "organizerAutoSendEnabled" setting (default on). De-duplicates so the
     * same request isn't added twice when multiple findings share one payload.
     * Falls back to sending the captured request/response when no confirmed-vuln
     * evidence could be matched (e.g. only suspected findings).
     */
    private void sendVulnsToOrganizer(ApiEntry entry, PipelineResult result) {
        try {
            if (configManager == null || !configManager.getConfig().isOrganizerAutoSendEnabled()) return;
            var verdict = result.verdict();
            if (verdict == null) return;
            if (verdict.confirmedVulns().isEmpty() && verdict.suspectedVulns().isEmpty()) return;

            java.util.Set<String> sentKeys = new java.util.HashSet<>();
            int sentCount = 0;

            for (ConfirmedVuln cv : verdict.confirmedVulns()) {
                PayloadResult evidence = VerdictValidator.findPayloadResult(result.payloadResults(), cv.payloadUsed());
                HttpRequestResponse[] rrs = toRequestResponses(entry, evidence);
                if (rrs.length > 0) {
                    String key = rrs[0].request().toString();
                    if (sentKeys.add(key)) {
                        api.organizer().sendToOrganizer(rrs[0]);
                        sentCount++;
                    }
                }
            }

            // Fallback: nothing matched (only suspected findings) → send the captured
            // request/response so the endpoint is still available in the Organizer.
            if (sentCount == 0) {
                HttpRequestResponse rr = buildEntryRequestResponse(entry);
                if (rr != null) {
                    api.organizer().sendToOrganizer(rr);
                    sentCount = 1;
                }
            }

            if (sentCount > 0) {
                logger.info("[Organizer] 已发送 %d 条证据请求到 Organizer: %s", sentCount, entry.getApiPath());
            }
        } catch (Exception e) {
            logger.debug("发送到 Organizer 失败: %s", e.getMessage());
        }
    }

    /** Build an HttpRequestResponse from the entry's last captured raw request/response.
     *  Static so both the auto-send path here and the manual "发送到 Organizer" action
     *  in the table (ApiSentinelPresenter) can reuse it. Returns null on anything missing. */
    /** Human-readable name for a Pipeline stage, used by the unified step cards. */
    static String pipelineStageName(int stage) {
        return switch (stage) {
            case 1 -> "流量分析（初步评估）";
            case 2 -> "代码关联";
            case 3 -> "生成测试Payload";
            case 4 -> "自动验证";
            case 5 -> "鉴权绕过检测";
            case 6 -> "AI综合研判";
            default -> "阶段" + stage;
        };
    }

    static HttpRequestResponse buildEntryRequestResponse(ApiEntry entry) {
        String rawReq = entry.getLastRawRequest();
        if (rawReq == null || rawReq.isEmpty()) return null;
        try {
            String domain = entry.getDomain() != null ? entry.getDomain() : "";
            boolean useHttps = entry.getLastUrl() == null || !entry.getLastUrl().startsWith("http://");
            String hostName = domain.contains(":") ? domain.split(":")[0] : domain;
            int port;
            if (domain.contains(":")) {
                try { port = Integer.parseInt(domain.split(":")[1]); }
                catch (NumberFormatException e) { port = useHttps ? 443 : 80; }
            } else {
                port = useHttps ? 443 : 80;
            }
            HttpService service = HttpService.httpService(hostName, port, useHttps);
            HttpRequest request = HttpRequest.httpRequest(service, rawReq);
            String rawResp = entry.getLastRawResponse();
            HttpResponse response = (rawResp != null && !rawResp.isEmpty())
                    ? HttpResponse.httpResponse(rawResp) : HttpResponse.httpResponse();
            return HttpRequestResponse.httpRequestResponse(request, response);
        } catch (Exception e) {
            return null;
        }
    }

    /** Builds a Montoya HttpRequestResponse from a PayloadResult's raw
     *  sent/received text so it can be attached as AuditIssue evidence —
     *  returns an empty array (not null) on anything missing/unparseable,
     *  since AuditIssue.auditIssue's requestResponses is a plain varargs and
     *  the issue should still get reported without evidence rather than fail
     *  entirely. */
    private HttpRequestResponse[] toRequestResponses(ApiEntry entry, PayloadResult pr) {
        if (pr == null || pr.sentRequest() == null || pr.sentRequest().isEmpty()) {
            return new HttpRequestResponse[0];
        }
        try {
            String domain = entry.getDomain() != null ? entry.getDomain() : "";
            boolean useHttps = entry.getLastUrl() == null || !entry.getLastUrl().startsWith("http://");
            String hostName = domain.contains(":") ? domain.split(":")[0] : domain;
            int port;
            if (domain.contains(":")) {
                try { port = Integer.parseInt(domain.split(":")[1]); }
                catch (NumberFormatException e) { port = useHttps ? 443 : 80; }
            } else {
                port = useHttps ? 443 : 80;
            }
            HttpService service = HttpService.httpService(hostName, port, useHttps);
            HttpRequest request = HttpRequest.httpRequest(service, pr.sentRequest());
            if (pr.receivedResponse() != null && !pr.receivedResponse().isEmpty()) {
                HttpResponse response = HttpResponse.httpResponse(pr.receivedResponse());
                return new HttpRequestResponse[]{HttpRequestResponse.httpRequestResponse(request, response)};
            }
            return new HttpRequestResponse[]{HttpRequestResponse.httpRequestResponse(request, HttpResponse.httpResponse())};
        } catch (Exception e) {
            logger.debug("构造 AuditIssue 证据请求失败: %s", e.getMessage());
            return new HttpRequestResponse[0];
        }
    }

    private String buildIssueDetail(ConfirmedVuln cv) {
        StringBuilder sb = new StringBuilder();
        sb.append("<b>漏洞类型:</b> ").append(escapeHtml(cv.type())).append("<br>");
        sb.append("<b>证据:</b> ").append(escapeHtml(cv.evidence())).append("<br>");
        if (cv.payloadUsed() != null && !cv.payloadUsed().isEmpty()) {
            sb.append("<b>触发 Payload:</b> <code>").append(escapeHtml(cv.payloadUsed())).append("</code><br>");
        }
        if (cv.response() != null && !cv.response().isEmpty()) {
            sb.append("<b>响应片段:</b> <pre>").append(escapeHtml(truncateStr(cv.response(), 500))).append("</pre><br>");
        }
        if (cv.verifyCommand() != null && !cv.verifyCommand().isEmpty()) {
            sb.append("<b>验证命令:</b> <code>").append(escapeHtml(cv.verifyCommand())).append("</code>");
        }
        return sb.toString();
    }

    private static String escapeHtml(String s) {
        if (s == null) return "";
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;");
    }

    private static String truncateStr(String s, int max) {
        if (s == null) return "";
        return s.length() <= max ? s : s.substring(0, max) + "...";
    }

    /** Shared by BatchOrchestrator's simple-analysis completion path too — static
     *  since it only needs the view/entry/riskLevel, no other instance state. */
    static void showHighRiskAlert(ApiSentinelTab view, ApiEntry entry, String riskLevel) {
        if (!"HIGH".equals(riskLevel) || view == null) return;
        SwingUtilities.invokeLater(() -> {
            ToastNotification.showVulnAlert(view, entry.getApiPath());
            Container parent = view.getParent();
            while (parent != null && !(parent instanceof JTabbedPane)) {
                parent = parent.getParent();
            }
            if (parent instanceof JTabbedPane burpTabs) {
                for (int i = 0; i < burpTabs.getTabCount(); i++) {
                    if (burpTabs.getComponentAt(i) == view) {
                        ToastNotification.flashTabCaption(burpTabs, burpTabs.getTitleAt(i), 10000);
                        break;
                    }
                }
            }
        });
    }
}
