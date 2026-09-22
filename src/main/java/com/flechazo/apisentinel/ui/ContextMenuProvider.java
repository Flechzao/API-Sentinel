package com.flechazo.apisentinel.ui;
import com.flechazo.apisentinel.event.UiEventBus;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import com.flechazo.apisentinel.logging.LeveledLogger;
import com.flechazo.apisentinel.matching.CompositeMatchEngine;
import com.flechazo.apisentinel.model.ApiEntry;
import com.flechazo.apisentinel.repository.ApiRepository;
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

    /** Callback to extract session credentials from a request into the
     *  auth-config panel. Signature: (slot "A" or "B", credentials). */
    private java.util.function.BiConsumer<String, com.flechazo.apisentinel.auth.SessionCredentials> extractSessionHandler;

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

    public void setExtractSessionHandler(java.util.function.BiConsumer<String, com.flechazo.apisentinel.auth.SessionCredentials> handler) {
        this.extractSessionHandler = handler;
    }

    @Override
    public List<Component> provideMenuItems(ContextMenuEvent event) {
        List<Component> items = new ArrayList<>();

        List<HttpRequestResponse> selected = event.selectedRequestResponses();
        if (selected == null || selected.isEmpty()) return items;

        // ========== Single top-level submenu ==========
        JMenu sentinel = new JMenu("API Sentinel");
        sentinel.setFont(theme.displayFont(Font.BOLD, 12f));

        // --- AI 分析 (primary action, follows toolbar mode toggle) ---
        JMenuItem analyzeItem = new JMenuItem("AI 分析");
        analyzeItem.setIcon(IconFactory.of(IconFactory.Kind.SEARCH, 14, theme.accentBg()));
        analyzeItem.setFont(theme.displayFont(Font.BOLD, 12f));
        analyzeItem.setToolTipText("根据工具栏模式执行 Agent 或 Pipeline 分析");
        analyzeItem.addActionListener(e -> sentinelPipelineFromContext(selected));
        sentinel.add(analyzeItem);

        sentinel.addSeparator();

        // --- 添加到监控列表 ---
        JMenuItem addApi = new JMenuItem("添加到监控列表");
        addApi.addActionListener(e -> addApiFromSelection(selected));
        sentinel.add(addApi);

        // --- 越权配置快捷操作 (3 sessions) ---
        JMenuItem extractSessionA = new JMenuItem("提取为会话 A（越权配置）");
        extractSessionA.addActionListener(e -> extractSessionFromContext(selected, "A"));
        sentinel.add(extractSessionA);

        JMenuItem extractSessionB = new JMenuItem("提取为会话 B（越权配置）");
        extractSessionB.addActionListener(e -> extractSessionFromContext(selected, "B"));
        sentinel.add(extractSessionB);

        JMenuItem extractSessionC = new JMenuItem("提取为会话 C（越权配置）");
        extractSessionC.addActionListener(e -> extractSessionFromContext(selected, "C"));
        sentinel.add(extractSessionC);

        items.add(sentinel);
        return items;
    }

    // ======================== Actions ========================

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
                logger.info("右键 AI 分析: %s %s", method, urlPath);
            } catch (Exception ex) {
                logger.error("右键 Pipeline 分析异常: %s", ex.getMessage());
            }
        }
        uiEventBus.postImmediateRefresh();
    }

    // ======================== Helpers ========================

    /**
     * Extract credentials from all selected requests and push them into the
     * auth-config panel as Session A, B, or C. When multiple requests are
     * selected, cookies and auth headers are merged (deduplicated by key),
     * so selecting 5 requests from the same user yields a complete credential
     * bundle rather than just the first request's headers.
     *
     * <p>After extraction, shows a toast with a credential preview so the
     * user gets immediate feedback about what was captured.
     */
    private void extractSessionFromContext(List<HttpRequestResponse> messages, String slot) {
        if (extractSessionHandler == null || messages.isEmpty()) {
            logger.warn("提取会话: handler 未注册或无选中请求");
            return;
        }
        // Merge credentials from ALL selected requests (not just the first).
        // Multiple requests from the same user may carry different cookies
        // (CSRF tokens, rotating session IDs) or different auth headers.
        java.util.Map<String, String> cookies = new java.util.LinkedHashMap<>();
        java.util.Map<String, String> authHeaders = new java.util.LinkedHashMap<>();
        for (HttpRequestResponse msg : messages) {
            if (msg.request() == null) continue;
            for (HttpHeader header : msg.request().headers()) {
                String name = header.name();
                String lower = name.toLowerCase();
                if ("cookie".equals(lower)) {
                    cookies.putAll(com.flechazo.apisentinel.auth.SessionDiscovery.parseCookies(header.value()));
                } else if (com.flechazo.apisentinel.util.AuthHeaders.isAuthHeader(lower) && !"cookie".equals(lower)) {
                    authHeaders.putIfAbsent(name, header.value());
                }
            }
        }
        com.flechazo.apisentinel.auth.SessionCredentials creds =
                new com.flechazo.apisentinel.auth.SessionCredentials(cookies, authHeaders);
        if (creds.isEmpty()) {
            logger.warn("提取会话: 选中的 %d 个请求均没有认证信息", messages.size());
            ToastNotification.show(null,
                    "选中的请求均没有认证信息（Cookie 或 Auth 头）",
                    ToastNotification.ToastType.WARNING, 3000);
            return;
        }
        extractSessionHandler.accept(slot, creds);
        String preview = creds.preview();
        String msg = messages.size() > 1
                ? String.format("已提取 %d 个请求的凭证到会话 %s — %s", messages.size(), slot, preview)
                : String.format("已提取到会话 %s — %s", slot, preview);
        logger.info("右键提取为会话 %s: %s (%d cookies, %d auth headers)",
                slot, preview, cookies.size(), authHeaders.size());
        ToastNotification.show(null, msg, ToastNotification.ToastType.SUCCESS, 3000);
    }

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
