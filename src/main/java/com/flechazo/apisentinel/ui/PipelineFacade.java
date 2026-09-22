package com.flechazo.apisentinel.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.flechazo.apisentinel.ai.pipeline.AnalysisPipeline;
import com.flechazo.apisentinel.ai.pipeline.PayloadResult;
import com.flechazo.apisentinel.ai.pipeline.AnalysisConfig;
import com.flechazo.apisentinel.ai.pipeline.PipelineResult;
import com.flechazo.apisentinel.ai.provider.LlmProvider;
import com.flechazo.apisentinel.codeindex.CodeIndexService;
import com.flechazo.apisentinel.config.ConfigManager;
import com.flechazo.apisentinel.logging.LeveledLogger;
import com.flechazo.apisentinel.model.ApiEntry;
import com.flechazo.apisentinel.model.ApiEntryTableModel;
import com.flechazo.apisentinel.repository.ApiRepository;

import javax.swing.JTabbedPane;
import javax.swing.SwingUtilities;
import java.awt.Container;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Pipeline Facade——编排 Pipeline (6-stage deterministic) 分析的启动、进度回调。
 * <p>
 * 共享的完成处理（状态更新、报告持久化、SiteMap、Organizer、级联触发等）
 * 委托给 {@link AnalysisCompletionHandler}——Agent 模式也使用同一 Handler，
 * 消除了原先 AgentFacade → PipelineFacade 的直接依赖。
 * <p>
 * Deliberately doesn't know about Agent mode or batch orchestration: the
 * Agent-mode routing decision lives in AiPresenter (the only place that
 * needs to know both PipelineFacade and AgentFacade exist), and batch
 * completion is reported back via the injected onDone callback rather than
 * this class reaching into BatchOrchestrator's state directly.
 */
class PipelineFacade {

    private final MontoyaApi api;
    private final ConfigManager configManager;
    private final ApiEntryTableModel tableModel;
    private final com.flechazo.apisentinel.ai.queue.AnalysisTaskQueue analysisQueue;
    private final CodeIndexService codeIndexService;
    private final LeveledLogger logger;
    private final java.util.Set<AnalysisPipeline> activePipelines = ConcurrentHashMap.newKeySet();
    /** 共享的分析完成处理器——Agent 和 Pipeline 共用。 */
    private final AnalysisCompletionHandler completionHandler;

    private ApiSentinelTab view;

    PipelineFacade(MontoyaApi api, ConfigManager configManager, ApiEntryTableModel tableModel,
                   com.flechazo.apisentinel.ai.queue.AnalysisTaskQueue analysisQueue,
                   CodeIndexService codeIndexService, LeveledLogger logger,
                   AnalysisCompletionHandler completionHandler) {
        this.api = api;
        this.configManager = configManager;
        this.tableModel = tableModel;
        this.analysisQueue = analysisQueue;
        this.codeIndexService = codeIndexService;
        this.logger = logger;
        this.completionHandler = completionHandler;
    }

    void setView(ApiSentinelTab view) {
        this.view = view;
        completionHandler.setView(view);
    }

    /** Ask every in-flight Pipeline run to stop (chat stop button). */
    void cancelAll() {
        for (AnalysisPipeline p : activePipelines) {
            try { p.cancel(); } catch (Exception ignored) {}
        }
    }

    void setLearnedRuleEngine(com.flechazo.apisentinel.ai.rules.LearnedRuleEngine engine) {
        completionHandler.setLearnedRuleEngine(engine);
    }
    void setMcpTools(com.flechazo.apisentinel.mcp.McpTools tools) {
        completionHandler.setMcpTools(tools);
    }
    void setEventBus(com.flechazo.apisentinel.event.EventBus eventBus) {
        completionHandler.setEventBus(eventBus);
    }
    void setPatternStore(com.flechazo.apisentinel.ai.patterns.PatternStore store) {
        completionHandler.setPatternStore(store);
    }
    void setRepository(ApiRepository repository) {
        completionHandler.setRepository(repository);
    }

    void shutdown() {
        for (AnalysisPipeline p : activePipelines) {
            try { p.cancel(); } catch (Exception ignored) {}
        }
        for (AnalysisPipeline p : activePipelines) {
            try { p.shutdown(); } catch (Exception ignored) {}
        }
        activePipelines.clear();
    }

    /** @param onDone called exactly once, on either completion or error. */
    void executePipelineForEntry(ApiEntry entry, LlmProvider provider, Runnable onDone) {
        var appConfig = configManager.getConfig();
        boolean authTestEnabled = appConfig.isUnauthorizedDetectionEnabled();
        AnalysisConfig pipelineConfig = AnalysisConfig.forPipeline(appConfig, authTestEnabled);
        AnalysisPipeline pipeline = new AnalysisPipeline(
                provider, api, codeIndexService, pipelineConfig,
                configManager.getConfig().getCodeRepos(), logger);
        if (view != null && view.getAiSettingsPanel() != null) {
            pipeline.setFastModel(view.getAiSettingsPanel().getFastModel());
        }
        pipeline.setReuseWindowMinutes(appConfig.getAnalysisReuseWindowMinutes());
        pipeline.setIncludeRawCredentials(appConfig.isIncludeRawCredentialsInLlm());
        activePipelines.add(pipeline);

        AiAnalysisPanel panel = view != null ? view.getAiAnalysisPanel() : null;
        AiChatPanel chatPanel = view != null ? view.getAiChatPanel() : null;
        final String entryPath = entry.getApiPath();

        var taskRecord = analysisQueue.addExternalRecord(entry.getApiPath(), "Pipeline");

        if (chatPanel != null) chatPanel.setAnalysisActive(true);
        tableModel.markAnalyzing(entry.getApiPath());
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

    /** Delegates to {@link AnalysisCompletionHandler#buildSummaryForChat}. */
    String buildPipelineSummaryForChat(ApiEntry entry, PipelineResult result) {
        return completionHandler.buildSummaryForChat(entry, result, "Pipeline");
    }

    String buildSummaryForChat(ApiEntry entry, PipelineResult result, String modeLabel) {
        return completionHandler.buildSummaryForChat(entry, result, modeLabel);
    }

    /** Delegates to {@link AnalysisCompletionHandler#handleComplete}. */
    void handlePipelineComplete(ApiEntry entry, PipelineResult result, AiAnalysisPanel panel, String mode) {
        completionHandler.handleComplete(entry, result, panel, mode);
    }

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

    /** Build an HttpRequestResponse from entry's captured raw request/response.
     *  Static so both internal use and external callers (ApiSentinelPresenter)
     *  can reuse it. Returns null on anything missing. */
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

    /** Shared by BatchOrchestrator's simple-analysis completion path too. */
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
