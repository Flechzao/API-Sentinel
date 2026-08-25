package com.flechazo.apisentinel.handler;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.Annotations;
import burp.api.montoya.core.HighlightColor;
import burp.api.montoya.http.handler.*;
import burp.api.montoya.http.message.HttpRequestResponse;
import com.flechazo.apisentinel.config.ConfigManager;
import com.flechazo.apisentinel.detection.HeuristicDetector;
import com.flechazo.apisentinel.detection.SensitiveInfoDetector;
import com.flechazo.apisentinel.detection.UnauthorizedDetector;
import com.flechazo.apisentinel.event.ApiMatchedEvent;
import com.flechazo.apisentinel.event.EventBus;
import com.flechazo.apisentinel.logging.LeveledLogger;
import com.flechazo.apisentinel.matching.CompositeMatchEngine;
import com.flechazo.apisentinel.model.ApiEntry;
import com.flechazo.apisentinel.model.ApiStatus;
import com.flechazo.apisentinel.model.PassiveFinding;
import com.flechazo.apisentinel.repository.ApiRepository;
import com.flechazo.apisentinel.ui.UiEventBus;
import com.flechazo.apisentinel.util.UrlUtils;
import com.flechazo.apisentinel.util.FocusFilter;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.List;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

import static burp.api.montoya.http.handler.RequestToBeSentAction.continueWith;
import static burp.api.montoya.http.handler.ResponseReceivedAction.continueWith;

/**
 * HTTP 流量处理器——Burp Proxy 的 HttpHandler 实现。实时捕获代理流量，
 * 归一化为 ApiEntry 并触发被动检测。含速率限制和历史回填。
 */
public class HttpTrafficHandler implements HttpHandler {

    /** Passive scan (sensitive-info + 13-class heuristic regex) is CPU-bound and
     *  per-response; running it on Burp's response thread lags the proxy under
     *  high traffic. It runs on this dedicated bounded pool instead. */
    private static final int PASSIVE_SCAN_THREADS = 2;
    /** Best-effort queue: when full, scans are DROPPED (never block/back-pressure
     *  the proxy). 500 deep responses is far more than bursts produce. */
    private static final int PASSIVE_SCAN_QUEUE = 500;

    private final CompositeMatchEngine matchEngine;
    private final ApiRepository repository;
    private final ConfigManager configManager;
    private final SensitiveInfoDetector sensitiveDetector;
    private final UnauthorizedDetector unauthorizedDetector;
    private final UiEventBus uiEventBus;
    private final EventBus eventBus;
    private final LeveledLogger logger;
    private final MontoyaApi api;
    private final HeuristicDetector heuristicDetector;
    private final ThreadPoolExecutor passiveScanPool;
    private final AtomicLong droppedScans = new AtomicLong();

    public HttpTrafficHandler(MontoyaApi api,
                              CompositeMatchEngine matchEngine,
                              ApiRepository repository,
                              ConfigManager configManager,
                              SensitiveInfoDetector sensitiveDetector,
                              UnauthorizedDetector unauthorizedDetector,
                              UiEventBus uiEventBus,
                              EventBus eventBus,
                              LeveledLogger logger) {
        this.api = api;
        this.matchEngine = matchEngine;
        this.repository = repository;
        this.configManager = configManager;
        this.sensitiveDetector = sensitiveDetector;
        this.unauthorizedDetector = unauthorizedDetector;
        this.uiEventBus = uiEventBus;
        this.eventBus = eventBus;
        this.logger = logger;
        this.heuristicDetector = new HeuristicDetector(logger);
        this.passiveScanPool = new ThreadPoolExecutor(
                PASSIVE_SCAN_THREADS, PASSIVE_SCAN_THREADS,
                0L, TimeUnit.MILLISECONDS,
                new LinkedBlockingQueue<>(PASSIVE_SCAN_QUEUE),
                r -> {
                    Thread t = new Thread(r, "api-sentinel-passive-scan");
                    t.setDaemon(true);
                    return t;
                },
                (r, executor) -> {
                    // Passive scans are best-effort: drop (and count) rather than
                    // apply back-pressure to Burp's response thread.
                    long n = droppedScans.incrementAndGet();
                    if ((n & 0xFF) == 1) {
                        logger.warn("被动检测队列已满，累计丢弃 %d 次扫描", n);
                    }
                });
    }

    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent request) {
        return continueWith(request);
    }

    @Override
    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived response) {
        try {
            String url = response.initiatingRequest().url();
            String urlPath = UrlUtils.extractPath(url);

            if (UrlUtils.isStaticResource(urlPath)) {
                return continueWith(response);
            }

            String method = response.initiatingRequest().method();

            // Always skip non-business methods (CORS preflight OPTIONS, HEAD)
            // regardless of focus mode — they have no auth/business semantics
            // and pollute API entries + trigger false unauth-detector hits.
            if (FocusFilter.isExcludedMethod(method, configManager.getConfig().getFocusExcludeMethods())) {
                return continueWith(response);
            }



            String requestBody = response.initiatingRequest().bodyToString();

            List<ApiEntry> matches = matchEngine.match(urlPath, requestBody);

            if (!matches.isEmpty()) {
                ApiEntry patternEntry = matches.get(0);
                logger.debug("匹配到API: %s %s -> %s", method, urlPath, patternEntry.getApiPath());

                String host = UrlUtils.stripPort(UrlUtils.extractHost(url));
                String rawRequest = buildRawRequest(response.initiatingRequest());
                String responseBody = response.bodyToString();
                String rawResponse = buildRawResponse(response);
                int statusCode = response.statusCode();

                // Find or create a method-specific entry
                ApiEntry matched;
                if (!repository.contains(method, patternEntry.getApiPath())) {
                    ApiEntry newEntry = new ApiEntry(method, patternEntry.getApiPath());
                    newEntry.setDomain(host);
                    repository.add(newEntry);
                    matched = newEntry;
                } else {
                    matched = repository.findByMethodAndPath(method, patternEntry.getApiPath()).orElse(patternEntry);
                }

                synchronized (matched) {
                    if (!host.isEmpty()) {
                        matched.setDomain(host);
                    }
                    matched.setLastSeenTimestamp(System.currentTimeMillis());
                    matched.setLastRawRequest(rawRequest);
                    matched.setLastUrl(url);
                    matched.setLastStatusCode(statusCode);
                    matched.setLastRawResponse(rawResponse);

                    if (matched.getStatus() == ApiStatus.UNTESTED) {
                        matched.updateStatus(ApiStatus.UNDER_TEST, null, ApiStatus.UNDER_TEST.getDisplayName());
                    }
                }

                eventBus.publish(new ApiMatchedEvent(matched, url, method, requestBody, responseBody, statusCode, rawRequest, rawResponse));

                // Highlight: respect the user toggle — when off, no color is set
                // on Proxy history annotations (keeps old tested entries clean).
                HighlightColor color = configManager.getConfig().isHighlightEnabled()
                        ? matched.getStatus().getHighlightColor() : HighlightColor.NONE;
                if (matched.getVulnType() != null) {
                    color = matched.getVulnType().getHighlightColor();
                }

                if (configManager.getConfig().isUnauthorizedDetectionEnabled()) {
                    // Already async internally (its own bounded pool does the
                    // auth-stripped replay); only dedup/rate-limit checks run here.
                    unauthorizedDetector.detect(response.initiatingRequest(), matched);
                }

                // Apply base annotation (status/vuln-type color + result note)
                // synchronously via the live annotations handle — the same idiom
                // ProxyHistoryScanner/ContextMenuProvider use for deferred
                // annotation updates. The passive-scan color UPGRADE arrives
                // asynchronously once the regex scans finish (below).
                Annotations annotations = response.annotations();
                annotations.setNotes(matched.getResult());
                annotations.setHighlightColor(color);

                // Passive regex scans (sensitive info + 13-class heuristics) are
                // CPU-bound — run them off Burp's response thread. Only plain
                // Java values cross the thread boundary: Strings, our own
                // ApiEntry (internally synchronized), the annotations handle and
                // config flags captured NOW (a mid-flight config toggle must not
                // change an already-queued scan's behavior).
                final boolean sensitiveEnabled = configManager.getConfig().isSensitiveDetectionEnabled();
                final boolean highlightEnabled = configManager.getConfig().isHighlightEnabled();
                final String fMethod = method;
                final String fUrl = url;
                final String fRawRequest = rawRequest;
                final String fRawResponse = rawResponse;
                final int fStatusCode = statusCode;
                final ApiEntry fMatched = matched;
                final Annotations fAnnotations = annotations;
                passiveScanPool.execute(() -> {
                    try {
                        runPassiveScans(fMatched, fAnnotations, fMethod, fUrl,
                                fRawRequest, fRawResponse, fStatusCode,
                                sensitiveEnabled, highlightEnabled);
                    } catch (Exception scanEx) {
                        logger.error("被动检测任务异常: %s", scanEx.getMessage());
                    }
                });

                uiEventBus.postTableRefresh();

                return continueWith(response);
            }
        } catch (Exception e) {
            StringWriter sw = new StringWriter();
            e.printStackTrace(new PrintWriter(sw));
            logger.error("处理HTTP响应时异常: %s\n%s", e.getMessage(), sw.toString());
        }

        return continueWith(response);
    }

    /**
     * Sensitive-info + heuristic regex scans and their note/annotation effects.
     * Runs on the passive-scan pool — MUST NOT touch Montoya objects; only the
     * extracted strings/entry/annotations handle captured at dispatch time.
     */
    private void runPassiveScans(ApiEntry matched, Annotations annotations,
                                 String method, String url,
                                 String rawRequest, String rawResponse, int statusCode,
                                 boolean sensitiveEnabled, boolean highlightEnabled) {
        boolean findingsChanged = false;

        if (sensitiveEnabled) {
            // Scan full raw messages (headers + body) so secrets in
            // Set-Cookie / X-Auth-Token / Location headers are caught too;
            // each rule's scope decides which side is scanned.
            List<com.flechazo.apisentinel.detection.SensitiveInfoDetector.SensitiveMatch> findings =
                    sensitiveDetector.detect(rawRequest, rawResponse);
            if (!findings.isEmpty()) {
                boolean addedAny = false;
                synchronized (matched) {
                    for (var match : findings) {
                        // One finding per rule — structured (source,title)
                        // dedup replaces the old note.contains(combined)
                        // guard (which mis-fired when hit order varied).
                        // evidence carries the matched fragment (truncated).
                        addedAny |= matched.addPassiveFindingIfAbsent(new PassiveFinding(
                                PassiveFinding.newId(), PassiveFinding.Source.SENSITIVE_INFO,
                                "INFO", "敏感信息", match.ruleName(), match.matchedValue(), "",
                                System.currentTimeMillis()));
                    }
                }
                if (addedAny) {
                    repository.markDirty(); // old note-era code never marked dirty here
                    findingsChanged = true;
                }
            }
        }

        HighlightColor heuristicColor = HighlightColor.NONE;
        try {
            var heuristics = heuristicDetector.detect(method, url, rawRequest, rawResponse, statusCode);
            if (!heuristics.isEmpty()) {
                // Highlight color reflects THIS response's findings every
                // time, independent of the finding-level dedup below.
                for (var h : heuristics) {
                    if ("HIGH".equals(h.risk())) {
                        heuristicColor = HighlightColor.RED;
                    } else if ("MEDIUM".equals(h.risk()) && heuristicColor != HighlightColor.RED) {
                        heuristicColor = HighlightColor.ORANGE;
                    } else if ("LOW".equals(h.risk())
                            && heuristicColor != HighlightColor.RED
                            && heuristicColor != HighlightColor.ORANGE) {
                        heuristicColor = HighlightColor.CYAN;
                    }
                }
                boolean addedAny = false;
                synchronized (matched) {
                    for (var h : heuristics) {
                        addedAny |= matched.addPassiveFindingIfAbsent(new PassiveFinding(
                                PassiveFinding.newId(), PassiveFinding.Source.HEURISTIC,
                                h.risk(), h.category(), h.title(),
                                h.evidence(), h.remediation(), System.currentTimeMillis()));
                    }
                }
                if (addedAny) {
                    repository.markDirty();
                    findingsChanged = true;
                }
            }
        } catch (Exception heuristicEx) {
            logger.debug("启发式检测异常: %s", heuristicEx.getMessage());
        }

        // Deferred highlight upgrade: heuristic findings outrank the base
        // status color applied synchronously (same precedence as before the
        // async split). No-op when highlight is disabled or nothing found.
        if (highlightEnabled && heuristicColor != HighlightColor.NONE) {
            try {
                annotations.setHighlightColor(heuristicColor);
            } catch (Exception annEx) {
                // Annotation handle going stale must never kill the scan —
                // the findings are already stored on the entry.
                logger.debug("异步更新高亮标注失败: %s", annEx.getMessage());
            }
        }

        if (findingsChanged) {
            uiEventBus.postTableRefresh();
        }
    }

    /** Stop accepting scans and terminate the pool (extension unload). */
    public void shutdown() {
        passiveScanPool.shutdownNow();
        try {
            passiveScanPool.awaitTermination(3, TimeUnit.SECONDS);
        } catch (InterruptedException ignored) {
            Thread.currentThread().interrupt();
        }
        long dropped = droppedScans.get();
        if (dropped > 0) {
            logger.info("被动检测累计因队列满丢弃 %d 次扫描", dropped);
        }
    }

    /** Test/diagnostic hook: number of passive scans dropped due to a full queue. */
    long getDroppedScanCount() {
        return droppedScans.get();
    }

    /**
     * Build a human-readable raw HTTP request string from a Montoya request object.
     */
    private String buildRawRequest(burp.api.montoya.http.message.requests.HttpRequest request) {
        return com.flechazo.apisentinel.util.HttpMessageUtils.buildRawRequest(request);
    }

    /**
     * Build a human-readable raw HTTP response string from a Montoya response object.
     */
    private String buildRawResponse(burp.api.montoya.http.message.responses.HttpResponse response) {
        return com.flechazo.apisentinel.util.HttpMessageUtils.buildRawResponse(response);
    }

    private static String truncate(String s, int maxLen) {
        if (s == null) return "";
        return s.length() <= maxLen ? s : s.substring(0, maxLen) + "\n...[truncated]";
    }
}
