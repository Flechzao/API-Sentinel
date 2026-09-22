package com.flechazo.apisentinel.browser;

import com.flechazo.apisentinel.logging.LeveledLogger;
import com.flechazo.apisentinel.repository.ApiRepository;
import com.microsoft.playwright.Page;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Unified browser service entry point.
 *
 * <p>Provides high-level methods for browser-based security testing:
 * <ul>
 *   <li>{@link #discoverApis(String, int)} - Discover APIs from frontend</li>
 *   <li>{@link #renderPage(String)} - Render page and extract DOM</li>
 *   <li>{@link #detectDomXss(String)} - Check for DOM XSS vulnerabilities</li>
 * </ul>
 *
 * <p>Thread-safe singleton pattern. Browser is lazily started on first use.
 */
public class BrowserService {

    private final BrowserManager manager;
    private final NetworkMonitor networkMonitor;
    private final JsAnalyzer jsAnalyzer;
    private final LeveledLogger logger;
    private final ApiRepository repository;

    /** Track discovered APIs to avoid duplicates in repository. */
    private final Set<String> discoveredKeys = ConcurrentHashMap.newKeySet();

    /** Default Burp proxy port (can be overridden via configure). */
    private static final int DEFAULT_BURP_PORT = 8080;

    /** Maximum pages to visit during discovery. */
    private int maxPages = 10;
    /** Frontend base URL for reverse page location (e.g. "http://localhost:3000"). */
    private String frontendBaseUrl = "";
    /** PageLocator for reverse API→page mapping. */
    private final PageLocator pageLocator;

    public BrowserService(LeveledLogger logger, ApiRepository repository) {
        this.logger = logger;
        this.repository = repository;
        this.manager = new BrowserManager(logger);
        this.networkMonitor = new NetworkMonitor(logger);
        this.jsAnalyzer = new JsAnalyzer(logger);
        this.pageLocator = new PageLocator(logger);

        // Default configuration
        manager.configure(DEFAULT_BURP_PORT, true, null);
    }

    /**
     * Configure the browser service.
     *
     * @param burpProxyPort Burp proxy port
     * @param headless whether to run headless
     * @param chromePath optional custom Chrome path
     * @param maxPages max pages to visit during discovery
     */
    public void configure(int burpProxyPort, boolean headless, String chromePath, int maxPages) {
        manager.configure(burpProxyPort, headless, chromePath);
        this.maxPages = maxPages > 0 ? maxPages : 10;
    }

    /**
     * Reconfigure browser settings and restart if already running.
     * Called when the user changes browser config in settings (headless, chromePath, etc.)
     * without requiring a full extension reload.
     */
    public void reconfigure(int burpProxyPort, boolean headless, String chromePath,
                            int maxPages, String frontendUrl) {
        boolean wasRunning = manager.isRunning();
        if (wasRunning) {
            logger.info("[BrowserService] 重新配置浏览器（先关闭再重启）");
            manager.close();
        }
        configure(burpProxyPort, headless, chromePath, maxPages);
        setFrontendBaseUrl(frontendUrl);
        if (wasRunning) {
            // Next browser operation will auto-start with new config
            logger.info("[BrowserService] 浏览器将在下次使用时以新配置启动 (headless=%s)", headless);
        }
    }

    /**
     * Check if browser is available and running.
     */
    public boolean isAvailable() {
        return manager.isRunning();
    }

    /**
     * Get the underlying BrowserManager (for advanced operations like BrowserLogin).
     */
    public BrowserManager getBrowserManager() {
        return manager;
    }

    /**
     * Discover APIs from a frontend application.
     *
     * <p>Navigates to the URL, monitors network requests, analyzes JS bundles,
     * and extracts frontend routes.
     *
     * @param url the starting URL
     * @param exploreDepth exploration depth: 1=shallow, 2=medium, 3=deep
     * @return discovery results
     */
    public DiscoveryResult discoverApis(String url, int exploreDepth) {
        logger.info("[BrowserService] 开始接口发现: %s (depth=%d)", url, exploreDepth);

        Page page = null;
        try {
            page = manager.getSharedPage();
            PageRenderer renderer = new PageRenderer(page, logger);

            // Start network monitoring
            networkMonitor.startMonitoring(page);

            // Navigate to the page
            if (!renderer.navigate(url)) {
                return new DiscoveryResult(List.of(), List.of(), List.of(), List.of(),
                        "Navigation failed");
            }

            // Wait a bit for dynamic content
            page.waitForTimeout(2000);

            // Extract frontend routes
            List<String> frontendRoutes = renderer.extractFrontendRoutes();

            // Save routes for later use by findPageForApi Level 2
            this.lastDiscoveredRoutes = new ArrayList<>(frontendRoutes);

            // Get script URLs for analysis
            List<String> scriptUrls = renderer.getScriptUrls();

            // Analyze JS bundles
            JsAnalyzer.JsAnalysisResult jsResult = jsAnalyzer.analyze(page, scriptUrls);

            // Explore linked pages based on depth
            if (exploreDepth >= 2) {
                exploreLinks(page, renderer, Math.min(exploreDepth * 3, maxPages));
            }

            // Stop monitoring
            networkMonitor.stopMonitoring();

            // Combine all discovered APIs
            List<DiscoveredApi> allApis = new ArrayList<>(networkMonitor.getUniqueApis());
            allApis.addAll(jsResult.apiEndpoints());

            // Add frontend routes as potential API endpoints
            for (String route : frontendRoutes) {
                if (!route.contains(":")) {  // Skip parameterized routes
                    allApis.add(DiscoveredApi.fromRouter(route, url));
                }
            }

            // Deduplicate
            List<DiscoveredApi> uniqueApis = allApis.stream()
                    .filter(api -> discoveredKeys.add(api.method() + " " + api.path()))
                    .toList();

            String summary = String.format("发现 %d 个 API (%d 网络, %d JS, %d 路由), %d 个密钥, %d 个 XSS sink",
                    uniqueApis.size(), networkMonitor.getCount(), jsResult.apiEndpoints().size(),
                    frontendRoutes.size(), jsResult.secrets().size(), jsResult.xssSinks().size());

            logger.info("[BrowserService] %s", summary);

            return new DiscoveryResult(uniqueApis, jsResult.secrets(),
                    jsResult.internalUrls(), jsResult.xssSinks(), summary);

        } catch (Exception e) {
            logger.error("[BrowserService] 接口发现失败: %s", e.getMessage());
            return new DiscoveryResult(List.of(), List.of(), List.of(), List.of(),
                    "Error: " + e.getMessage());
        } finally {
            if (page != null) {
                closePageGracefully(page);
            }
        }
    }

    /**
     * Render a page and extract DOM information.
     *
     * @param url the URL to render
     * @return render results
     */
    public RenderResult renderPage(String url) {
        logger.info("[BrowserService] 渲染页面: %s", url);

        Page page = null;
        try {
            page = manager.getSharedPage();
            PageRenderer renderer = new PageRenderer(page, logger);

            if (!renderer.navigate(url)) {
                return new RenderResult("", "", List.of(), List.of(), List.of(), "Navigation failed");
            }

            String dom = renderer.getRenderedDom();
            String title = renderer.getTitle();
            List<String> consoleLogs = renderer.getConsoleLogs();
            List<String> cspViolations = renderer.getCspViolations();
            List<String> frontendRoutes = renderer.extractFrontendRoutes();

            return new RenderResult(dom, title, consoleLogs, cspViolations, frontendRoutes, "OK");

        } catch (Exception e) {
            logger.error("[BrowserService] 渲染失败: %s", e.getMessage());
            return new RenderResult("", "", List.of(), List.of(), List.of(), "Error: " + e.getMessage());
        } finally {
            if (page != null) {
                closePageGracefully(page);
            }
        }
    }

    /**
     * Detect DOM XSS vulnerabilities on a page.
     *
     * @param url the URL to test
     * @return XSS detection results
     */
    public DomXssResult detectDomXss(String url) {
        logger.info("[BrowserService] DOM XSS 检测: %s", url);

        Page page = null;
        try {
            page = manager.getSharedPage();
            PageRenderer renderer = new PageRenderer(page, logger);

            if (!renderer.navigate(url)) {
                return new DomXssResult(false, List.of(), "", false, "Navigation failed");
            }

            // Get script URLs and analyze for sinks
            List<String> scriptUrls = renderer.getScriptUrls();
            JsAnalyzer.JsAnalysisResult jsResult = jsAnalyzer.analyze(page, scriptUrls);

            // Test with a canary payload in URL hash
            String testUrl = url + "#<img/src=x onerror=alert(1)>";
            renderer.navigate(testUrl);
            page.waitForTimeout(1000);

            // Check if the payload was reflected/executed
            List<String> cspViolations = renderer.getCspViolations();
            boolean cspBlocked = !cspViolations.isEmpty();

            // Check console for XSS-related errors
            List<String> consoleLogs = renderer.getConsoleLogs();
            boolean xssExecuted = consoleLogs.stream()
                    .anyMatch(log -> log.contains("alert") || log.contains("onerror"));

            String status = xssExecuted ? "XSS executed!" :
                    cspBlocked ? "Blocked by CSP" :
                    jsResult.xssSinks().isEmpty() ? "No sinks found" : "Sinks found but not triggered";

            return new DomXssResult(xssExecuted, jsResult.xssSinks(), status, cspBlocked, "OK");

        } catch (Exception e) {
            logger.error("[BrowserService] DOM XSS 检测失败: %s", e.getMessage());
            return new DomXssResult(false, List.of(), "", false, "Error: " + e.getMessage());
        } finally {
            if (page != null) {
                closePageGracefully(page);
            }
        }
    }

    /**
     * Register discovered APIs to the repository.
     *
     * @param apis list of discovered APIs
     * @return number of newly registered APIs
     */
    public int registerDiscoveredApis(List<DiscoveredApi> apis) {
        int registered = 0;
        for (DiscoveredApi api : apis) {
            String key = api.method() + " " + api.path();
            if (discoveredKeys.add(key)) {
                // Check if already in repository
                boolean exists = repository.findByMethodAndPath(api.method(), api.path()).isPresent();
                if (!exists) {
                    repository.add(api.toApiEntry(""));
                    registered++;
                }
            }
        }
        logger.info("[BrowserService] 注册了 %d 个新 API", registered);
        return registered;
    }

    // ========== F-1b: Reverse Page Location & UI Interaction ==========

    /**
     * Set the frontend base URL for reverse page location.
     *
     * @param url frontend base URL (e.g. "http://localhost:3000")
     */
    public void setFrontendBaseUrl(String url) {
        this.frontendBaseUrl = url != null ? url.replaceAll("/+$", "") : "";
    }

    /**
     * Reverse-locate which frontend page invokes a given API endpoint.
     *
     * <p>Three-level strategy (degrading):
     * <ol>
     *   <li>JS Bundle search — scan loaded JS for the API path (high confidence)</li>
     *   <li>Crawl mapping — visit routes, record which APIs each page fires (medium)</li>
     *   <li>RESTful path inference — guess from API resource name (low, always available)</li>
     * </ol>
     *
     * @param apiMethod   HTTP method of the target API (e.g. "POST")
     * @param apiPath     API path (e.g. "/api/v1/orders")
     * @param frontendBaseUrl optional override for the configured frontend base URL
     * @return location result with candidate pages and strategy used
     */
    public PageLocationResult findPageForApi(String apiMethod, String apiPath, String frontendBaseUrl) {
        String baseUrl = (frontendBaseUrl != null && !frontendBaseUrl.isEmpty())
                ? frontendBaseUrl.replaceAll("/+$", "")
                : this.frontendBaseUrl;

        logger.info("[BrowserService] 反向定位: %s %s (baseUrl=%s)", apiMethod, apiPath, baseUrl);

        List<PageLocator.CandidatePage> allCandidates = new ArrayList<>();
        String strategy = "none";

        // Level 1: JS Bundle search (needs a loaded page + a real URL)
        if (manager.isRunning() && !baseUrl.isEmpty()) {
            Page page = null;
            try {
                page = manager.getSharedPage();
                String searchUrl = baseUrl.isEmpty() ? "about:blank" : baseUrl;
                page.navigate(searchUrl, new Page.NavigateOptions().setTimeout(10000));
                page.waitForTimeout(2000);

                List<PageLocator.CandidatePage> jsResults =
                        pageLocator.searchInJsBundles(page, apiPath, baseUrl);
                if (!jsResults.isEmpty()) {
                    allCandidates.addAll(jsResults);
                    strategy = "js_bundle";
                    logger.info("[BrowserService] Level 1 命中: %d 个候选", jsResults.size());
                }
            } catch (Exception e) {
                logger.warn("[BrowserService] Level 1 JS Bundle 搜索失败: %s", e.getMessage());
            } finally {
                if (page != null) {
                    try { closePageGracefully(page); } catch (Exception ignored) {}
                }
            }
        }

        // Level 2: Crawl mapping (if we have routes from previous browser_discover)
        if (allCandidates.isEmpty() && !baseUrl.isEmpty()) {
            try {
                // Use routes from last discovery run
                List<String> knownRoutes = lastDiscoveredRoutes;
                if (!knownRoutes.isEmpty()) {
                    Map<String, Set<String>> mapping =
                            pageLocator.buildApiPageMapping(baseUrl, knownRoutes, maxPages, manager);
                    Set<String> pages = mapping.get(apiPath);
                    if (pages != null) {
                        for (String pageUrl : pages) {
                            allCandidates.add(new PageLocator.CandidatePage(
                                    pageUrl, "medium",
                                    "Crawl mapping: page fires " + apiPath));
                        }
                        if (!allCandidates.isEmpty()) {
                            strategy = "crawl_map";
                            logger.info("[BrowserService] Level 2 命中: %d 个候选", allCandidates.size());
                        }
                    }
                }
            } catch (Exception e) {
                logger.warn("[BrowserService] Level 2 爬取映射失败: %s", e.getMessage());
            }
        }

        // Level 3: RESTful path inference (always available)
        if (allCandidates.isEmpty()) {
            List<PageLocator.CandidatePage> inferred =
                    pageLocator.inferFromApiPath(apiPath, baseUrl);
            allCandidates.addAll(inferred);
            strategy = "path_inference";
            logger.info("[BrowserService] Level 3 推断: %d 个候选", inferred.size());
        }

        boolean found = !allCandidates.isEmpty();
        String message = found
                ? String.format("找到 %d 个候选页面 (策略: %s)", allCandidates.size(), strategy)
                : "未找到匹配的前端页面";

        return new PageLocationResult(found, strategy, allCandidates, message);
    }

    /** Routes discovered in the last browser_discover call (reused by Level 2). */
    private volatile List<String> lastDiscoveredRoutes = List.of();

    /**
     * Navigate to a page and execute a sequence of UI actions, optionally
     * capturing the network request triggered by the interaction.
     *
     * <p>Supported action types:
     * <ul>
     *   <li>{@code wait_for} — wait for a CSS selector to appear</li>
     *   <li>{@code click} — click an element</li>
     *   <li>{@code fill} — fill an input/textarea with a value</li>
     *   <li>{@code select} — select an option from a dropdown</li>
     *   <li>{@code check} — check a checkbox</li>
     *   <li>{@code type} — type character-by-character (simulates real keyboard)</li>
     *   <li>{@code wait_for_request} — wait for a matching network request</li>
     * </ul>
     *
     * @param url            page URL to navigate to
     * @param actions        ordered list of actions to execute
     * @param captureNetwork whether to capture network requests
     * @return interaction result with action outcomes and captured request
     */
    public InteractionResult interact(String url, List<BrowserAction> actions, boolean captureNetwork) {
        logger.info("[BrowserService] UI 交互: %s (%d 个动作)", url, actions.size());

        Page page = null;
        try {
            page = manager.getSharedPage();
            PageRenderer renderer = new PageRenderer(page, logger);

            // Start network monitoring if requested
            if (captureNetwork) {
                networkMonitor.startMonitoring(page);
            }

            // Navigate to the page
            if (!renderer.navigate(url)) {
                return new InteractionResult(false, List.of(), null, url, "Navigation failed");
            }

            // Execute actions sequentially
            List<ActionResult> results = new ArrayList<>();
            CapturedRequest capturedRequest = null;

            for (int i = 0; i < actions.size(); i++) {
                BrowserAction action = actions.get(i);
                ActionResult result = executeAction(renderer, action, i + 1);
                results.add(result);

                // If wait_for_request succeeded, capture the request
                if ("wait_for_request".equals(action.type()) && result.success() && result.capturedRequest() != null) {
                    capturedRequest = result.capturedRequest();
                }

                // Stop on failure
                if (!result.success()) {
                    logger.warn("[BrowserService] 动作 %d 失败: %s — 停止执行", i + 1, result.message());
                    break;
                }
            }

            if (captureNetwork) {
                networkMonitor.stopMonitoring();
            }

            String currentUrl = renderer.getCurrentUrl();
            String message = String.format("执行了 %d/%d 个动作", results.size(), actions.size());

            return new InteractionResult(true, results, capturedRequest, currentUrl, message);

        } catch (Exception e) {
            logger.error("[BrowserService] UI 交互失败: %s", e.getMessage());
            return new InteractionResult(false, List.of(), null, url, "Error: " + e.getMessage());
        } finally {
            if (page != null) {
                try { closePageGracefully(page); } catch (Exception ignored) {}
            }
        }
    }

    /**
     * Execute a single browser action.
     */
    private ActionResult executeAction(PageRenderer renderer, BrowserAction action, int step) {
        String type = action.type();
        String selector = action.selector();
        int timeout = action.timeoutMs() > 0 ? action.timeoutMs() : 5000;

        try {
            return switch (type) {
                case "wait_for" -> {
                    boolean ok = renderer.waitForSelector(selector, timeout);
                    yield new ActionResult(step, type, ok,
                            ok ? "Element found: " + selector : "Timeout waiting for: " + selector, null);
                }
                case "click" -> {
                    boolean ok = renderer.click(selector);
                    yield new ActionResult(step, type, ok,
                            ok ? "Clicked: " + selector : "Click failed: " + selector, null);
                }
                case "fill" -> {
                    boolean ok = renderer.fill(selector, action.value());
                    yield new ActionResult(step, type, ok,
                            ok ? "Filled: " + selector : "Fill failed: " + selector, null);
                }
                case "select" -> {
                    boolean ok = renderer.select(selector, action.value());
                    yield new ActionResult(step, type, ok,
                            ok ? "Selected: " + action.value() : "Select failed: " + selector, null);
                }
                case "check" -> {
                    boolean ok = renderer.check(selector);
                    yield new ActionResult(step, type, ok,
                            ok ? "Checked: " + selector : "Check failed: " + selector, null);
                }
                case "type" -> {
                    boolean ok = renderer.type(selector, action.value(), action.delayMs());
                    yield new ActionResult(step, type, ok,
                            ok ? "Typed into: " + selector : "Type failed: " + selector, null);
                }
                case "wait_for_request" -> {
                    CapturedRequest req = renderer.waitForRequest(
                            action.urlPattern() != null ? action.urlPattern() : "*", timeout);
                    boolean ok = req != null;
                    yield new ActionResult(step, type, ok,
                            ok ? "Request captured: " + req.method() + " " + req.url()
                               : "Timeout waiting for request: " + action.urlPattern(),
                            req);
                }
                case "hover" -> {
                    boolean ok = renderer.hover(selector);
                    yield new ActionResult(step, type, ok,
                            ok ? "Hovered: " + selector : "Hover failed: " + selector, null);
                }
                case "scroll" -> {
                    boolean ok = renderer.scrollTo(selector, action.value());
                    yield new ActionResult(step, type, ok,
                            ok ? "Scrolled: " + (selector != null ? selector : action.value())
                               : "Scroll failed", null);
                }
                case "upload" -> {
                    boolean ok = renderer.uploadFile(selector, action.value());
                    yield new ActionResult(step, type, ok,
                            ok ? "Uploaded: " + action.value() + " → " + selector
                               : "Upload failed: " + selector, null);
                }
                case "press_key" -> {
                    boolean ok = renderer.pressKey(selector, action.value());
                    yield new ActionResult(step, type, ok,
                            ok ? "Pressed: " + action.value()
                               : "Press key failed: " + action.value(), null);
                }
                default -> new ActionResult(step, type, false,
                        "Unknown action type: " + type, null);
            };
        } catch (Exception e) {
            return new ActionResult(step, type, false,
                    "Exception: " + e.getMessage(), null);
        }
    }

    /** Check if browser is running in headless mode. */
    public boolean isHeadless() {
        return manager.isHeadless();
    }

    /**
     * In non-headless mode, pause briefly before closing a page so the user
     * can see what the browser did (navigation, form filling, etc.).
     * In headless mode, close immediately (no visual feedback needed).
     *
     * <p>For shared pages (from {@code getSharedPage()}), this is a no-op —
     * the page should persist across tool calls to avoid the annoying UX
     * of tabs popping open and closing.
     */
    private void closePageGracefully(Page page) {
        if (page == null) return;
        // Don't close the shared page — it's reused across tool calls
        if (manager.isSharedPage(page)) return;
        if (!manager.isHeadless()) {
            try { Thread.sleep(2000); } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
        try { page.close(); } catch (Exception ignored) {}
    }

    /**
     * Shutdown the browser service and release resources.
     */
    public void shutdown() {
        manager.close();
        discoveredKeys.clear();
    }

    /**
     * Explore linked pages from the current page.
     */
    private void exploreLinks(Page page, PageRenderer renderer, int maxLinks) {
        try {
            Object links = page.evaluate("""
                (() => {
                    const anchors = document.querySelectorAll('a[href]');
                    const hrefs = [];
                    for (const a of anchors) {
                        const href = a.href;
                        if (href && href.startsWith(window.location.origin) && !href.includes('#')) {
                            hrefs.push(href);
                        }
                        if (hrefs.length >= %d) break;
                    }
                    return hrefs;
                })()
                """.formatted(maxLinks));

            if (links instanceof List<?> list) {
                int visited = 0;
                for (Object link : list) {
                    if (visited >= maxLinks) break;
                    if (link instanceof String url) {
                        renderer.navigate(url);
                        page.waitForTimeout(1000);
                        visited++;
                    }
                }
            }
        } catch (Exception e) {
            logger.warn("[BrowserService] 探索链接失败: %s", e.getMessage());
        }
    }

    // ========== Result Records ==========

    /**
     * Result of API discovery.
     */
    public record DiscoveryResult(
            List<DiscoveredApi> apis,
            List<JsAnalyzer.SecretFinding> secrets,
            List<String> internalUrls,
            List<String> xssSinks,
            String summary
    ) {}

    /**
     * Result of page rendering.
     */
    public record RenderResult(
            String dom,
            String title,
            List<String> consoleLogs,
            List<String> cspViolations,
            List<String> frontendRoutes,
            String status
    ) {}

    /**
     * Result of DOM XSS detection.
     */
    public record DomXssResult(
            boolean xssDetected,
            List<String> sinksFound,
            String status,
            boolean cspBlocked,
            String message
    ) {}

    // ========== F-1b: Reverse Page Location & UI Interaction Records ==========

    /**
     * Result of reverse-locating which frontend page invokes a given API.
     *
     * @param found      whether any candidate pages were found
     * @param strategy   which strategy produced the results ("js_bundle", "crawl_map", "path_inference", "none")
     * @param candidates list of candidate pages with confidence and reason
     * @param message    human-readable summary
     */
    public record PageLocationResult(
            boolean found,
            String strategy,
            List<PageLocator.CandidatePage> candidates,
            String message
    ) {}

    /**
     * Result of a UI interaction sequence.
     *
     * @param success          whether all actions executed successfully
     * @param actionResults    per-step outcomes
     * @param capturedRequest  network request captured by wait_for_request (may be null)
     * @param currentUrl       the page URL after interaction (may differ if navigation occurred)
     * @param message          human-readable summary
     */
    public record InteractionResult(
            boolean success,
            List<ActionResult> actionResults,
            CapturedRequest capturedRequest,
            String currentUrl,
            String message
    ) {}

    /**
     * Outcome of a single UI action step.
     *
     * @param step             1-based step number in the action sequence
     * @param type             action type ("click", "fill", "wait_for", etc.)
     * @param success          whether the action succeeded
     * @param message          human-readable description of the outcome
     * @param capturedRequest  non-null only for wait_for_request actions that succeeded
     */
    public record ActionResult(
            int step,
            String type,
            boolean success,
            String message,
            CapturedRequest capturedRequest
    ) {}

    /**
     * A UI action to execute in browser_interact.
     *
     * @param type       action type: "wait_for", "click", "fill", "select", "check", "type", "wait_for_request"
     * @param selector   CSS/XPath selector (null for wait_for_request)
     * @param value      value for fill/select/type (null for others)
     * @param timeoutMs  timeout in milliseconds (0 = default)
     * @param urlPattern glob pattern for wait_for_request (null for others)
     * @param delayMs    delay between keystrokes for type action (0 = instant)
     */
    public record BrowserAction(
            String type,
            String selector,
            String value,
            int timeoutMs,
            String urlPattern,
            int delayMs
    ) {}
}
