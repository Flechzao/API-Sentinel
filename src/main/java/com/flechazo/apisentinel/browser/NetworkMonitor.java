package com.flechazo.apisentinel.browser;

import com.flechazo.apisentinel.logging.LeveledLogger;
import com.microsoft.playwright.*;

import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import java.util.regex.Pattern;

/**
 * Monitors browser network requests and captures API calls.
 *
 * <p>Filters out static resources (images, CSS, fonts) and focuses on
 * XHR/Fetch requests that are likely API calls.
 */
public class NetworkMonitor {

    /** Resource types to ignore (static assets). */
    private static final Set<String> IGNORED_RESOURCE_TYPES = Set.of(
            "image", "stylesheet", "font", "media", "manifest", "ping"
    );

    /** URL patterns to ignore (common static file extensions). */
    private static final Pattern STATIC_URL_PATTERN = Pattern.compile(
            "\\.(png|jpg|jpeg|gif|svg|ico|css|woff|woff2|ttf|eot|mp4|webm)(\\?.*)?$",
            Pattern.CASE_INSENSITIVE
    );

    /** URL patterns that indicate API calls. */
    private static final Pattern API_URL_PATTERN = Pattern.compile(
            "(/api/|/v[0-9]+/|\\.json|/graphql|/rest/)",
            Pattern.CASE_INSENSITIVE
    );

    private final LeveledLogger logger;
    private final List<DiscoveredApi> capturedApis = new CopyOnWriteArrayList<>();
    private String currentPageUrl = "";
    private boolean monitoring = false;
    private Page monitoredPage;
    /** Last captured request headers — useful for BrowserInteractTool to include
     *  auth tokens in captured requests. Stores up to 100 entries. */
    private final java.util.concurrent.ConcurrentHashMap<String, Map<String, String>> requestHeaders =
            new java.util.concurrent.ConcurrentHashMap<>();

    public NetworkMonitor(LeveledLogger logger) {
        this.logger = logger;
    }

    /**
     * Start monitoring network requests on a page.
     *
     * @param page the Playwright page to monitor
     */
    public void startMonitoring(Page page) {
        if (monitoring) return;

        monitoring = true;
        monitoredPage = page;
        capturedApis.clear();

        // Capture request information
        page.onRequest(request -> {
            currentPageUrl = page.url();

            String resourceType = request.resourceType();
            String url = request.url();

            // Skip ignored resource types
            if (IGNORED_RESOURCE_TYPES.contains(resourceType)) return;

            // Skip static file URLs
            if (STATIC_URL_PATTERN.matcher(url).find()) return;

            // Only capture XHR/Fetch or API-like URLs
            boolean isXhrOrFetch = "xhr".equals(resourceType) || "fetch".equals(resourceType);
            boolean looksLikeApi = API_URL_PATTERN.matcher(url).find();

            if (!isXhrOrFetch && !looksLikeApi) return;

            // Extract path from URL
            String path = extractPath(url);
            if (path == null || path.isEmpty()) return;

            String method = request.method();
            String postData = request.postData() != null ? request.postData() : "";

            // Store the discovered API
            DiscoveredApi api = DiscoveredApi.fromNetwork(method, path, postData, "", currentPageUrl);
            capturedApis.add(api);

            // Record request headers for later use (e.g. BrowserInteractTool)
            Map<String, String> headers = request.headers();
            String headerKey = method + " " + path;
            requestHeaders.put(headerKey, headers);
            // Cap the header cache to prevent unbounded growth
            if (requestHeaders.size() > 100) {
                var firstKey = requestHeaders.keys().nextElement();
                requestHeaders.remove(firstKey);
            }

            logger.debug("[NetworkMonitor] 捕获 API: %s %s", method, path);
        });

        // Optionally capture response for additional context
        page.onResponse(response -> {
            String url = response.url();
            String path = extractPath(url);

            // Find matching captured API and update with response info
            for (int i = 0; i < capturedApis.size(); i++) {
                DiscoveredApi api = capturedApis.get(i);
                if (api.path().equals(path) && api.responseSnippet().isEmpty()) {
                    try {
                        String body = response.body() != null ? new String(response.body()) : "";
                        String snippet = body.length() > 500 ? body.substring(0, 500) + "..." : body;
                        capturedApis.set(i, new DiscoveredApi(
                                api.method(), api.path(), api.source(),
                                api.requestBody(), snippet, api.discoveredIn()
                        ));
                    } catch (Exception ignored) {
                        // Response body may not be available
                    }
                    break;
                }
            }
        });

        logger.debug("[NetworkMonitor] 开始监控网络请求");
    }

    /**
     * Stop monitoring.
     */
    public void stopMonitoring() {
        monitoring = false;
        monitoredPage = null;
        logger.info("[NetworkMonitor] 停止监控，共捕获 %d 个 API", capturedApis.size());
    }

    /**
     * Get all captured API endpoints.
     */
    public List<DiscoveredApi> getCapturedApis() {
        return List.copyOf(capturedApis);
    }

    /**
     * Get only unique API endpoints (deduplicated by method+path).
     */
    public List<DiscoveredApi> getUniqueApis() {
        return capturedApis.stream()
                .collect(java.util.stream.Collectors.toMap(
                        api -> api.method() + " " + api.path(),
                        api -> api,
                        (existing, replacement) -> existing,
                        java.util.LinkedHashMap::new
                ))
                .values()
                .stream()
                .toList();
    }

    /**
     * Clear captured APIs.
     */
    public void clear() {
        capturedApis.clear();
        requestHeaders.clear();
    }

    /**
     * Get the count of captured APIs.
     */
    public int getCount() {
        return capturedApis.size();
    }

    /**
     * Get recorded headers for a specific API endpoint.
     *
     * @param method HTTP method
     * @param path   API path
     * @return headers map, or null if not recorded
     */
    public Map<String, String> getHeadersFor(String method, String path) {
        return requestHeaders.get(method + " " + path);
    }

    /**
     * Block until a network request matching the given URL pattern is observed,
     * then return the full request details including headers.
     *
     * <p>The URL pattern supports simple globs: {@code *} matches any sequence
     * (e.g. {@code "*&#47;api&#47;v1&#47;orders*"}).

    /**
     * Extract path from a full URL.
     */
    private String extractPath(String url) {
        if (url == null) return null;
        try {
            int schemeEnd = url.indexOf("://");
            if (schemeEnd < 0) return url;
            int pathStart = url.indexOf('/', schemeEnd + 3);
            if (pathStart < 0) return "/";
            int queryStart = url.indexOf('?', pathStart);
            return queryStart > 0 ? url.substring(pathStart, queryStart) : url.substring(pathStart);
        } catch (Exception e) {
            return null;
        }
    }
}
