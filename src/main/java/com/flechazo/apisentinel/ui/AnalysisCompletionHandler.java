package com.flechazo.apisentinel.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import com.flechazo.apisentinel.ai.pipeline.ConfirmedVuln;
import com.flechazo.apisentinel.ai.pipeline.FinalVerdict;
import com.flechazo.apisentinel.ai.pipeline.PayloadResult;
import com.flechazo.apisentinel.ai.pipeline.PipelineResult;
import com.flechazo.apisentinel.ai.pipeline.SuspectedVuln;
import com.flechazo.apisentinel.ai.pipeline.VerdictValidator;
import com.flechazo.apisentinel.ai.pipeline.VulnEndpointAttributor;
import com.flechazo.apisentinel.ai.pipeline.PipelineReportWriter;
import com.flechazo.apisentinel.ai.rules.LearnedRuleEngine;
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

/**
 * 分析完成后的共享处理逻辑——被 Pipeline 和 Agent 两种模式共同使用。
 * <p>
 * 职责：状态更新、规则学习、Pattern 保存、级联触发、报告持久化、
 * Burp SiteMap 上报、Organizer 发送。
 * <p>
 * 从 {@link PipelineFacade} 提取，消除 AgentFacade → PipelineFacade 的
 * 直接依赖——两种分析引擎平等地依赖此 Handler，而非 Agent 寄居在 Pipeline 之下。
 */
class AnalysisCompletionHandler {

    private final MontoyaApi api;
    private final ConfigManager configManager;
    private final ApiEntryTableModel tableModel;
    private final LeveledLogger logger;

    private ApiSentinelTab view;
    private LearnedRuleEngine learnedRuleEngine;
    private com.flechazo.apisentinel.mcp.McpTools mcpTools;
    private com.flechazo.apisentinel.event.EventBus eventBus;
    private com.flechazo.apisentinel.ai.patterns.PatternStore patternStore;
    private ApiRepository repository;

    AnalysisCompletionHandler(MontoyaApi api, ConfigManager configManager,
                              ApiEntryTableModel tableModel, LeveledLogger logger) {
        this.api = api;
        this.configManager = configManager;
        this.tableModel = tableModel;
        this.logger = logger;
    }

    void setView(ApiSentinelTab view) { this.view = view; }
    void setLearnedRuleEngine(LearnedRuleEngine engine) { this.learnedRuleEngine = engine; }
    void setMcpTools(com.flechazo.apisentinel.mcp.McpTools tools) { this.mcpTools = tools; }
    void setEventBus(com.flechazo.apisentinel.event.EventBus eventBus) { this.eventBus = eventBus; }
    void setPatternStore(com.flechazo.apisentinel.ai.patterns.PatternStore store) { this.patternStore = store; }
    void setRepository(ApiRepository repository) { this.repository = repository; }

    /**
     * 分析完成后的统一处理入口——Pipeline 和 Agent 都调此方法。
     * 负责：记录 AnalysisRecord → 状态更新 → 跨端点归因 → 级联触发 →
     * MCP 事件推送 → 表格刷新 → 结论上屏 → 高危提醒 → SiteMap/Reporter →
     * 规则学习 → Pattern 保存 → 报告落盘。
     *
     * @param mode "PIPELINE" or "AGENT" — stored on the AnalysisRecord and
     *             shown in the status label.
     */
    void handleComplete(ApiEntry entry, PipelineResult result, AiAnalysisPanel panel, String mode) {
        logger.info("[%s] 完成: %s -> %s", mode, entry.getApiPath(), result.verdict().overallRisk());

        AnalysisRecord record = new AnalysisRecord(mode, result.trafficAnalysis());
        record = record.withTestCases(result.testCases());
        record = record.withPipelineResult(result);
        if (panel != null && panel.getTimelinePanel() != null) {
            record = record.withTimeline(panel.getTimelinePanel().getEvents());
        }
        entry.addAnalysisRecord(record);
        tableModel.markRepositoryDirty();

        // Each sink is isolated in its own try/catch so one failure can never
        // abort the completion flow before the verdict/progress/report UI settles.
        try {
            updateEntryStatusFromVerdict(entry, result.verdict());
        } catch (Throwable t) {
            logger.warn("[完成流程] 状态列更新失败: %s", t.getMessage());
        }

        try {
            attributeCrossEndpointVulns(entry, result.verdict());
        } catch (Throwable t) {
            logger.warn("[完成流程] 跨端点归因失败（不影响结果展示）: %s", t.getMessage());
        }

        try {
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

        reportToSiteMap(entry, result);
        sendVulnsToOrganizer(entry, result);

        if (learnedRuleEngine != null && result.trafficAnalysis() != null
                && result.trafficAnalysis().isSuccess()) {
            learnedRuleEngine.learnFromAnalysis(entry.getApiPath(), result.trafficAnalysis());
        }

        if (patternStore != null && result.verdict() != null) {
            patternStore.recordConfirmations(entry, result.verdict());
        }

        savePipelineReport(entry, result);
        saveHtmlReport(entry, result, panel);
    }

    /**
     * 生成分析结果的聊天摘要 Markdown——Pipeline 和 Agent 共用。
     */
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
        sb.append("你可以针对以上结果继续追问，例如「这个漏洞怎么利用」或「给出绕过方案」。");
        return sb.toString();
    }

    // ─── Private helpers ──────────────────────────────────────────────

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
            return;
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

    private void savePipelineReport(ApiEntry entry, PipelineResult result) {
        try {
            PipelineReportWriter reportWriter = new PipelineReportWriter(logger);
            List<Object> chatHistory = List.of();
            if (view != null) {
                AiChatPanel chatPanel = view.getAiChatPanel();
                if (chatPanel != null) {
                    chatHistory = chatPanel.getCurrentHistory().stream()
                            .map(msg -> (Object) java.util.Map.of("role", msg.role(), "content",
                                    msg.content() != null && msg.content().length() > 5000
                                            ? msg.content().substring(0, 5000) + "...[truncated]"
                                            : (msg.content() != null ? msg.content() : "")))
                            .toList();
                }
            }
            java.nio.file.Path reportPath = reportWriter.saveReportWithChat(
                    entry, result, result.trafficStats(), chatHistory);
            if (reportPath != null) {
                logger.info("[完成] 分析报告已保存: %s", reportPath);
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
            logger.error("[完成] 保存分析报告失败: %s", e.getMessage());
        }
    }

    private void saveHtmlReport(ApiEntry entry, PipelineResult result, AiAnalysisPanel panel) {
        try {
            com.flechazo.apisentinel.ai.pipeline.HtmlReportWriter htmlWriter =
                    new com.flechazo.apisentinel.ai.pipeline.HtmlReportWriter(logger);
            var outcome = htmlWriter.saveReportEx(entry, result);
            switch (outcome.kind()) {
                case SAVED -> {
                    java.nio.file.Path htmlPath = outcome.path();
                    logger.info("[完成] HTML 报告已保存: %s", htmlPath);
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
                }
                case NO_CONTENT ->
                    logger.info("[完成] 本次无确认/疑似漏洞，未生成 HTML 报告");
                case FAILED -> {
                    logger.error("[完成] HTML 报告保存失败: %s", outcome.errorMessage());
                    if (view != null) {
                        AiChatPanel chatPanel = view.getAiChatPanel();
                        if (chatPanel != null) {
                            chatPanel.appendProgressNote(
                                    "⚠️ HTML 报告保存失败: " + outcome.errorMessage()
                                    + " (JSON 完整日志仍可用)");
                        }
                    }
                }
            }
        } catch (Exception e) {
            logger.error("[完成] 保存 HTML 报告失败: %s", e.getMessage());
        }
    }

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
                PayloadResult evidence = VerdictValidator.findPayloadResult(result.payloadResults(), cv.payloadUsed());
                HttpRequestResponse[] requestResponses = toRequestResponses(entry, evidence);
                AuditIssue issue = AuditIssue.auditIssue(
                        "[API-Sentinel] " + cv.title(),
                        buildIssueDetail(cv),
                        cv.verifyCommand() != null ? cv.verifyCommand() : "",
                        baseUrl,
                        AuditIssueSeverity.HIGH,
                        AuditIssueConfidence.FIRM,
                        "API Sentinel 自动化分析确认的漏洞。类型: " + cv.type(),
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
                        "API Sentinel 分析识别的疑似漏洞，需要进一步手动验证。",
                        verdict.recommendations() != null ? verdict.recommendations() : "",
                        severity
                );
                api.siteMap().add(issue);
                logger.info("[SiteMap] 上报疑似漏洞: %s → %s", entry.getApiPath(), sv.title());
            }
        } catch (Exception e) {
            logger.warn("上报 SiteMap AuditIssue 失败: %s", e.getMessage());
        }
    }

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
            logger.warn("发送到 Organizer 失败: %s", e.getMessage());
        }
    }

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
            logger.warn("构造 AuditIssue 证据请求失败: %s", e.getMessage());
            return new HttpRequestResponse[0];
        }
    }

    private HttpRequestResponse buildEntryRequestResponse(ApiEntry entry) {
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

    private static void showHighRiskAlert(ApiSentinelTab view, ApiEntry entry, String riskLevel) {
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
