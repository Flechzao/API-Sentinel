package com.flechazo.apisentinel.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.Annotations;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import com.flechazo.apisentinel.logging.LeveledLogger;
import com.flechazo.apisentinel.matching.CompositeMatchEngine;
import com.flechazo.apisentinel.model.ApiEntry;
import com.flechazo.apisentinel.model.ApiStatus;
import com.flechazo.apisentinel.model.VulnType;
import com.flechazo.apisentinel.repository.ApiRepository;
import com.flechazo.apisentinel.util.BambdaCodeGen;
import com.flechazo.apisentinel.util.UrlUtils;

import javax.swing.*;
import java.awt.*;
import java.util.ArrayList;
import java.util.List;

/**
 * Context menu provider — all items live under a single "API Sentinel" submenu
 * to avoid cluttering Burp's native menu.
 */
public class ContextMenuProvider implements ContextMenuItemsProvider {

    private final MontoyaApi api;
    private final BurpTheme theme;
    private final ApiRepository repository;
    private final CompositeMatchEngine matchEngine;
    private final UiEventBus uiEventBus;
    private final LeveledLogger logger;

    /** Callback to trigger full Pipeline analysis for a given ApiEntry. */
    private java.util.function.Consumer<ApiEntry> pipelineAnalyzeHandler;

    public ContextMenuProvider(MontoyaApi api, ApiRepository repository,
                               CompositeMatchEngine matchEngine,
                               com.flechazo.apisentinel.ai.queue.AnalysisTaskQueue analysisQueue,
                               UiEventBus uiEventBus, LeveledLogger logger) {
        this.api = api;
        this.theme = new BurpTheme(api);
        this.repository = repository;
        this.matchEngine = matchEngine;
        this.uiEventBus = uiEventBus;
        this.logger = logger;
    }

    public void setPipelineAnalyzeHandler(java.util.function.Consumer<ApiEntry> handler) {
        this.pipelineAnalyzeHandler = handler;
    }

    @Override
    public List<Component> provideMenuItems(ContextMenuEvent event) {
        List<Component> items = new ArrayList<>();

        List<HttpRequestResponse> selected = event.selectedRequestResponses();
        if (selected == null || selected.isEmpty()) return items;

        // ========== Single top-level submenu ==========
        JMenu sentinel = new JMenu("API Sentinel");
        sentinel.setFont(theme.displayFont(Font.BOLD, 12f));

        // --- 🔍 Pipeline 分析 (primary action, prominent) ---
        JMenuItem pipelineItem = new JMenuItem("🔍 Pipeline 分析");
        pipelineItem.setFont(theme.displayFont(Font.BOLD, 12f));
        pipelineItem.setToolTipText("完整5阶段分析（流量→代码→Payload→验证→研判）");
        pipelineItem.addActionListener(e -> sentinelPipelineFromContext(selected));
        sentinel.add(pipelineItem);

        sentinel.addSeparator();

        // --- 添加到监控列表 ---
        JMenuItem addApi = new JMenuItem("添加到监控列表");
        addApi.addActionListener(e -> addApiFromSelection(selected));
        sentinel.add(addApi);

        // --- 标记状态 ▸ (submenu with specific states) ---
        JMenu statusMenu = new JMenu("标记状态");
        for (ApiStatus status : ApiStatus.values()) {
            JMenuItem item = new JMenuItem(status.getDisplayName());
            item.addActionListener(e -> setTestStatus(selected, status));
            statusMenu.add(item);
        }
        sentinel.add(statusMenu);

        // --- 标记漏洞 ▸ ---
        JMenu vulnMenu = new JMenu("标记漏洞");
        for (VulnType vt : VulnType.values()) {
            JMenuItem item = new JMenuItem(vt.getDisplayName());
            item.addActionListener(e -> markVulnerability(selected, vt));
            vulnMenu.add(item);
        }
        sentinel.add(vulnMenu);

        sentinel.addSeparator();

        // --- 生成 Bambda 代码 ---
        JMenuItem bambdaItem = new JMenuItem("生成 Bambda 代码");
        bambdaItem.addActionListener(e -> generateBambdaFromContext(selected));
        sentinel.add(bambdaItem);

        items.add(sentinel);
        return items;
    }

    // ======================== Actions ========================

    private void setTestStatus(List<HttpRequestResponse> messages, ApiStatus targetStatus) {
        for (HttpRequestResponse msg : messages) {
            String urlPath = UrlUtils.extractPath(msg.request().url());
            List<ApiEntry> matches = matchEngine.match(urlPath, null);
            if (!matches.isEmpty()) {
                ApiEntry entry = matches.get(0);
                if (targetStatus == ApiStatus.VULNERABLE) {
                    entry.updateStatus(targetStatus, VulnType.GENERIC, VulnType.GENERIC.getDisplayName());
                } else {
                    entry.updateStatus(targetStatus, null, targetStatus.getDisplayName());
                }
                Annotations annotations = Annotations.annotations(
                        entry.getResult(), entry.getStatus().getHighlightColor());
                msg.annotations().setHighlightColor(annotations.highlightColor());
                msg.annotations().setNotes(annotations.notes());
            }
        }
        uiEventBus.postImmediateRefresh();
    }

    private void addApiFromSelection(List<HttpRequestResponse> messages) {
        int added = 0;
        for (HttpRequestResponse msg : messages) {
            String method = msg.request().method();
            String url = msg.request().url();
            String apiPath = UrlUtils.extractPath(url);
            if (!repository.contains(method, apiPath)) {
                ApiEntry entry = new ApiEntry(method, apiPath);
                String host = UrlUtils.stripPort(UrlUtils.extractHost(url));
                entry.setDomain(host);
                // Also store traffic data if available
                entry.setLastUrl(url);
                if (msg.response() != null) entry.setLastStatusCode(msg.response().statusCode());
                storeTraffic(entry, msg);
                repository.add(entry);
                matchEngine.addEntry(entry);
                added++;
            }
        }
        if (added > 0) {
            logger.info("右键添加 %d 个 API 到监控列表", added);
            uiEventBus.postImmediateRefresh();
        }
    }

    private void markVulnerability(List<HttpRequestResponse> messages, VulnType vulnType) {
        for (HttpRequestResponse msg : messages) {
            String urlPath = UrlUtils.extractPath(msg.request().url());
            List<ApiEntry> matches = matchEngine.match(urlPath, null);
            if (!matches.isEmpty()) {
                ApiEntry entry = matches.get(0);
                entry.updateStatus(ApiStatus.VULNERABLE, vulnType, vulnType.getDisplayName());
                Annotations annotations = Annotations.annotations(
                        vulnType.getDisplayName(), vulnType.getHighlightColor());
                msg.annotations().setHighlightColor(annotations.highlightColor());
                msg.annotations().setNotes(annotations.notes());
                logger.info("标记漏洞: %s -> %s", entry.getApiPath(), vulnType.getDisplayName());
            }
        }
        uiEventBus.postImmediateRefresh();
    }

    private void sentinelPipelineFromContext(List<HttpRequestResponse> messages) {
        if (pipelineAnalyzeHandler == null) {
            logger.warn("Pipeline 分析未初始化（需要先完成插件加载）");
            return;
        }
        for (HttpRequestResponse msg : messages) {
            try {
                String url = msg.request().url();
                String urlPath = UrlUtils.extractPath(url);
                String method = msg.request().method();
                String host = UrlUtils.stripPort(UrlUtils.extractHost(url));

                // Find or create ApiEntry
                List<ApiEntry> matches = matchEngine.match(urlPath, null);
                ApiEntry entry;
                if (!matches.isEmpty()) {
                    entry = matches.get(0);
                } else {
                    entry = new ApiEntry(method, urlPath);
                    entry.setDomain(host);
                    repository.add(entry);
                    matchEngine.addEntry(entry);
                }

                // Store traffic data
                entry.setLastUrl(url);
                if (msg.response() != null) entry.setLastStatusCode(msg.response().statusCode());
                storeTraffic(entry, msg);

                pipelineAnalyzeHandler.accept(entry);
                logger.info("右键 Pipeline 分析: %s %s", method, urlPath);
            } catch (Exception ex) {
                logger.error("右键 Pipeline 分析异常: %s", ex.getMessage());
            }
        }
        uiEventBus.postImmediateRefresh();
    }

    private void generateBambdaFromContext(List<HttpRequestResponse> messages) {
        List<ApiEntry> entries = new ArrayList<>();
        for (HttpRequestResponse msg : messages) {
            String url = msg.request().url();
            String urlPath = UrlUtils.extractPath(url);
            List<ApiEntry> matches = matchEngine.match(urlPath, null);
            if (!matches.isEmpty()) {
                entries.add(matches.get(0));
            } else {
                ApiEntry temp = new ApiEntry(msg.request().method(), urlPath);
                temp.setDomain(UrlUtils.stripPort(UrlUtils.extractHost(url)));
                entries.add(temp);
            }
        }
        if (entries.isEmpty()) return;

        String code = entries.size() == 1
                ? BambdaCodeGen.generate(entries.get(0))
                : BambdaCodeGen.generateBatch(entries);
        java.awt.datatransfer.StringSelection sel = new java.awt.datatransfer.StringSelection(code);
        java.awt.Toolkit.getDefaultToolkit().getSystemClipboard().setContents(sel, null);
        logger.info("已生成 Bambda 代码并复制到剪贴板 (%d 个API)", entries.size());
    }

    // ======================== Helpers ========================

    /** Store raw request/response from HttpRequestResponse into ApiEntry. */
    private void storeTraffic(ApiEntry entry, HttpRequestResponse msg) {
        try {
            String method = msg.request().method();
            StringBuilder reqBuilder = new StringBuilder();
            reqBuilder.append(method).append(" ").append(msg.request().path()).append(" HTTP/1.1\n");
            for (HttpHeader header : msg.request().headers()) {
                reqBuilder.append(header.name()).append(": ").append(header.value()).append("\n");
            }
            reqBuilder.append("\n");
            String reqBody = msg.request().bodyToString();
            if (reqBody != null && !reqBody.isEmpty()) reqBuilder.append(truncate(reqBody, 5000));
            entry.setLastRawRequest(reqBuilder.toString());

            if (msg.response() != null) {
                StringBuilder respBuilder = new StringBuilder();
                respBuilder.append("HTTP/1.1 ").append(msg.response().statusCode()).append("\n");
                for (HttpHeader header : msg.response().headers()) {
                    respBuilder.append(header.name()).append(": ").append(header.value()).append("\n");
                }
                respBuilder.append("\n");
                String respBody = msg.response().bodyToString();
                if (respBody != null && !respBody.isEmpty()) respBuilder.append(truncate(respBody, 5000));
                entry.setLastRawResponse(respBuilder.toString());
            }
        } catch (Exception ignored) {}
    }

    private static String truncate(String s, int maxLen) {
        if (s == null) return "";
        return s.length() <= maxLen ? s : s.substring(0, maxLen) + "\n...[truncated]";
    }
}
