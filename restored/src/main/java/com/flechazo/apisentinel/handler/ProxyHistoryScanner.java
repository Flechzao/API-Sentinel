package com.flechazo.apisentinel.handler;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.Annotations;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;
import com.flechazo.apisentinel.config.ConfigManager;
import com.flechazo.apisentinel.logging.LeveledLogger;
import com.flechazo.apisentinel.matching.CompositeMatchEngine;
import com.flechazo.apisentinel.model.ApiEntry;
import com.flechazo.apisentinel.model.ApiStatus;
import com.flechazo.apisentinel.repository.ApiRepository;
import com.flechazo.apisentinel.ui.UiEventBus;
import com.flechazo.apisentinel.util.FocusFilter;
import com.flechazo.apisentinel.util.UrlUtils;

import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

public class ProxyHistoryScanner {

    private final MontoyaApi api;
    private final CompositeMatchEngine matchEngine;
    private final UiEventBus uiEventBus;
    private final LeveledLogger logger;
    private final ConfigManager configManager;
    private final ApiRepository repository;
    private final ExecutorService executor;
    private final AtomicBoolean scanning = new AtomicBoolean(false);

    public ProxyHistoryScanner(MontoyaApi api, CompositeMatchEngine matchEngine,
                               UiEventBus uiEventBus, LeveledLogger logger,
                               ConfigManager configManager, ApiRepository repository) {
        this.api = api;
        this.matchEngine = matchEngine;
        this.uiEventBus = uiEventBus;
        this.logger = logger;
        this.configManager = configManager;
        this.repository = repository;
        this.executor = Executors.newSingleThreadExecutor(r -> {
            Thread t = new Thread(r, "api-sentinel-history-scanner");
            t.setDaemon(true);
            return t;
        });
    }

    public void scanHistory() {
        if (!scanning.compareAndSet(false, true)) {
            logger.debug("历史扫描已在进行中，跳过重复请求");
            return;
        }

        executor.submit(() -> {
            try {
                List<ProxyHttpRequestResponse> history = api.proxy().history();
                logger.info("开始扫描代理历史记录: %d 条", history.size());
                int matchCount = 0;

                for (ProxyHttpRequestResponse item : history) {
                    try {
                        String url = item.finalRequest().url();
                        String urlPath = UrlUtils.extractPath(url);

                        if (UrlUtils.isStaticResource(urlPath)) continue;

                        String method = item.finalRequest().method();
                        String host = UrlUtils.stripPort(UrlUtils.extractHost(url));

                        // Apply the SAME focus-mode + non-business-method filter as the
                        if (FocusFilter.isExcludedMethod(method,
                                configManager.getConfig().getFocusExcludeMethods())) continue;

                        String requestBody = item.finalRequest().bodyToString();
                        List<ApiEntry> matches = matchEngine.match(urlPath, requestBody);

                        if (!matches.isEmpty()) {
                            ApiEntry matched = matches.get(0);

                            String rawRequest = com.flechazo.apisentinel.util.HttpMessageUtils.buildRawRequest(item.finalRequest());
                            String rawResponse = "";
                            int statusCode = 0;
                            if (item.response() != null) {
                                rawResponse = com.flechazo.apisentinel.util.HttpMessageUtils.buildRawResponse(item.response());
                                statusCode = item.response().statusCode();
                            }

                            synchronized (matched) {
                                matched.appendHttpMethod(method);
                                if (!host.isEmpty()) {
                                    matched.setDomain(host);
                                }
                                matched.setLastSeenTimestamp(System.currentTimeMillis());
                                matched.setLastRawRequest(rawRequest);
                                matched.setLastUrl(url);
                                if (statusCode > 0) {
                                    matched.setLastStatusCode(statusCode);
                                    matched.setLastRawResponse(rawResponse);
                                }
                                if (matched.getStatus() == ApiStatus.UNTESTED) {
                                    matched.updateStatus(ApiStatus.UNDER_TEST, null,
                                            ApiStatus.UNDER_TEST.getDisplayName() + "(历史接口检查)");
                                }
                            }

                            Annotations annotations = Annotations.annotations(
                                    matched.getResult(), matched.getStatus().getHighlightColor());
                            item.annotations().setHighlightColor(annotations.highlightColor());
                            item.annotations().setNotes(annotations.notes());

                            matchCount++;
                        }
                    } catch (Exception e) {
                        logger.debug("扫描历史记录项异常: %s", e.getMessage());
                    }
                }

                logger.info("历史记录扫描完成: 匹配到 %d 个API", matchCount);
                uiEventBus.postImmediateRefresh();
            } catch (Exception e) {
                logger.error("扫描历史记录失败", e);
            } finally {
                scanning.set(false);
            }
        });
    }

    public void shutdown() {
        executor.shutdownNow();
        try {
            executor.awaitTermination(3, TimeUnit.SECONDS);
        } catch (InterruptedException ignored) {
            Thread.currentThread().interrupt();
        }
    }
}
