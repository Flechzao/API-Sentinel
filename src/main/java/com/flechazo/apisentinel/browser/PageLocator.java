package com.flechazo.apisentinel.browser;

import com.flechazo.apisentinel.logging.LeveledLogger;
import com.microsoft.playwright.Page;

import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Reverse-locates which frontend page invokes a given API endpoint.
 *
 * <p>Three-level strategy (degrading):
 * <ol>
 *   <li><b>JS Bundle search</b> — scan already-loaded JS for the API path string (high confidence)</li>
 *   <li><b>Crawl mapping</b> — visit known frontend routes, record which APIs each page fires (medium-high)</li>
 *   <li><b>RESTful path inference</b> — guess frontend routes from the API resource name (low-medium, always available)</li>
 * </ol>
 */
public class PageLocator {

    private final LeveledLogger logger;

    /** Pattern to extract resource name segments from an API path. */
    private static final Pattern RESOURCE_SEGMENT = Pattern.compile(
            "/([a-zA-Z][a-zA-Z0-9_-]*)(?=/|$)");

    /** Common admin/management prefixes to try. */
    private static final List<String> PREFIX_VARIANTS = List.of(
            "", "/admin", "/manage", "/dashboard");

    /** Common path suffixes that suggest page routes. */
    private static final List<String> PAGE_SUFFIXES = List.of(
            "", "/new", "/create", "/edit", "/list", "/detail");

    public PageLocator(LeveledLogger logger) {
        this.logger = logger;
    }

    // ======================== Level 1: JS Bundle Search ========================

    /**
     * Search JS bundles loaded on the given page for references to the target API path.
     *
     * @param page    the Playwright page (must already be navigated to the frontend)
     * @param apiPath the target API path (e.g. "/api/v1/orders")
     * @param baseUrl the frontend base URL
     * @return candidate pages (may be empty if no match)
     */
    public List<CandidatePage> searchInJsBundles(Page page, String apiPath, String baseUrl) {
        List<CandidatePage> results = new ArrayList<>();

        try {
            // Get all script source URLs
            Object scripts = page.evaluate("""
                (() => {
                    return Array.from(document.querySelectorAll('script[src]'))
                        .map(s => s.src);
                })()
                """);

            if (!(scripts instanceof List<?> scriptList)) return results;

            // Normalize the API path for matching (strip path params like {id})
            String searchPath = apiPath.replaceAll("\\{[^}]+}", "").replaceAll("/+", "/");
            // Also try without version prefix: /api/v1/orders → /orders
            String shortPath = searchPath.replaceAll("^/api/v[0-9]+", "");

            for (Object scriptObj : scriptList) {
                if (!(scriptObj instanceof String scriptUrl)) continue;

                try {
                    // Fetch script content via page context
                    Object content = page.evaluate("""
                        (async (url) => {
                            try {
                                const resp = await fetch(url);
                                return await resp.text();
                            } catch(e) { return ''; }
                        })(%s)
                        """.formatted(jsString(scriptUrl)));

                    if (!(content instanceof String jsContent) || jsContent.isEmpty()) continue;

                    // Search for API path in JS content
                    boolean foundFull = jsContent.contains(searchPath);
                    boolean foundShort = !shortPath.isEmpty() && jsContent.contains(shortPath);

                    if (foundFull || foundShort) {
                        String matchedPath = foundFull ? searchPath : shortPath;
                        results.add(new CandidatePage(
                                page.url(),
                                "high",
                                String.format("JS bundle '%s' contains API path '%s'",
                                        shortScriptName(scriptUrl), matchedPath)));

                        logger.info("[PageLocator] Level 1 命中: %s 在 JS %s 中找到",
                                matchedPath, shortScriptName(scriptUrl));
                        break;  // One match is enough — same page
                    }
                } catch (Exception e) {
                    logger.warn("[PageLocator] 获取 JS 内容失败 %s: %s", scriptUrl, e.getMessage());
                }
            }
        } catch (Exception e) {
            logger.warn("[PageLocator] JS Bundle 搜索失败: %s", e.getMessage());
        }

        return results;
    }

    // ======================== Level 2: Crawl Mapping ========================

    /**
     * Visit frontend routes and record which APIs each page fires.
     *
     * <p>For each candidate route, navigates to the page using BrowserManager,
     * monitors network requests via NetworkMonitor, and records which API paths
     * are triggered. This builds a real API→page mapping based on observed behavior.
     *
     * @param baseUrl        frontend base URL
     * @param routes         list of frontend route paths (from browser_discover)
     * @param maxPages       maximum pages to visit
     * @param browserManager browser lifecycle manager (creates pages)
     * @return mapping from API path to the set of page URLs that fire it
     */
    public Map<String, Set<String>> buildApiPageMapping(String baseUrl, List<String> routes,
                                                        int maxPages, BrowserManager browserManager) {
        Map<String, Set<String>> mapping = new LinkedHashMap<>();

        if (baseUrl == null || baseUrl.isEmpty() || routes.isEmpty() || browserManager == null) {
            return mapping;
        }

        int visited = 0;
        for (String route : routes) {
            if (visited >= maxPages) break;

            // Skip parameterized routes
            if (route.contains(":") || route.contains("{")) continue;

            String pageUrl = baseUrl.replaceAll("/+$", "") + route;
            com.microsoft.playwright.Page tempPage = null;
            try {
                tempPage = browserManager.newPage();  // Intentionally new: crawling multiple routes in parallel
                NetworkMonitor routeMonitor = new NetworkMonitor(logger);
                routeMonitor.startMonitoring(tempPage);

                // Navigate and wait for initial requests
                tempPage.navigate(pageUrl, new com.microsoft.playwright.Page.NavigateOptions()
                        .setTimeout(10000)
                        .setWaitUntil(com.microsoft.playwright.options.WaitUntilState.NETWORKIDLE));
                tempPage.waitForTimeout(2000);  // wait for delayed API calls

                // Collect APIs fired by this page
                List<DiscoveredApi> pageApis = routeMonitor.getUniqueApis();
                for (DiscoveredApi api : pageApis) {
                    mapping.computeIfAbsent(api.path(), k -> new LinkedHashSet<>()).add(pageUrl);
                }

                routeMonitor.stopMonitoring();
                visited++;
            } catch (Exception e) {
                logger.warn("[PageLocator] 爬取路由 %s 失败: %s", pageUrl, e.getMessage());
            } finally {
                if (tempPage != null) {
                    try { tempPage.close(); } catch (Exception ignored) {}
                }
            }
        }

        logger.info("[PageLocator] 爬取映射完成: %d 个 API, %d 个页面", mapping.size(), visited);
        return mapping;
    }

    /**
     * Legacy overload without BrowserManager — returns route-to-page mapping only
     * (no real navigation). Use {@link #buildApiPageMapping(String, List, int, BrowserManager)}
     * for real API→page mapping.
     */
    public Map<String, Set<String>> buildApiPageMapping(String baseUrl, List<String> routes, int maxPages) {
        Map<String, Set<String>> mapping = new LinkedHashMap<>();
        if (baseUrl == null || baseUrl.isEmpty() || routes.isEmpty()) return mapping;

        int visited = 0;
        for (String route : routes) {
            if (visited >= maxPages) break;
            if (route.contains(":") || route.contains("{")) continue;
            String pageUrl = baseUrl.replaceAll("/+$", "") + route;
            mapping.computeIfAbsent(route, k -> new LinkedHashSet<>()).add(pageUrl);
            visited++;
        }
        return mapping;
    }

    // ======================== Level 3: RESTful Path Inference ========================

    /**
     * Infer candidate frontend pages from the API path using RESTful conventions.
     *
     * <p>Example: {@code POST /api/v1/users/123/roles} → {@code /users, /admin/users, /users/123/roles}
     *
     * @param apiPath the target API path
     * @param baseUrl the frontend base URL (may be empty)
     * @return candidate pages with low-medium confidence
     */
    public List<CandidatePage> inferFromApiPath(String apiPath, String baseUrl) {
        List<CandidatePage> results = new ArrayList<>();

        if (apiPath == null || apiPath.isEmpty()) return results;

        String base = (baseUrl != null && !baseUrl.isEmpty())
                ? baseUrl.replaceAll("/+$", "")
                : "";

        // Extract resource name segments
        List<String> segments = new ArrayList<>();
        Matcher m = RESOURCE_SEGMENT.matcher(apiPath);
        while (m.find()) {
            String seg = m.group(1);
            // Skip common non-resource segments
            if (!seg.matches("api|v[0-9]+|rest|graphql")) {
                segments.add(seg);
            }
        }

        if (segments.isEmpty()) {
            // Fallback: use the full path minus version prefix
            String fallback = apiPath.replaceAll("^/api/v[0-9]+", "");
            if (!fallback.isEmpty()) {
                results.add(new CandidatePage(base + fallback, "low",
                        "Fallback: direct path mapping"));
            }
            return results;
        }

        Set<String> candidates = new LinkedHashSet<>();

        // Primary resource: /users
        String primaryResource = segments.get(0);
        for (String prefix : PREFIX_VARIANTS) {
            candidates.add(prefix + "/" + primaryResource);
        }

        // With common page suffixes: /users/new, /users/list, /users/create
        for (String suffix : PAGE_SUFFIXES) {
            if (!suffix.isEmpty()) {
                candidates.add("/" + primaryResource + suffix);
            }
        }

        // If there are sub-resources: /users/{id}/roles → /users/detail/roles
        if (segments.size() >= 2) {
            String subResource = segments.get(segments.size() - 1);
            candidates.add("/" + primaryResource + "/detail/" + subResource);
            candidates.add("/" + primaryResource + "/" + subResource);
        }

        // Singular form variant: /users → /user (common in some frameworks)
        if (primaryResource.endsWith("s") && primaryResource.length() > 2) {
            String singular = primaryResource.substring(0, primaryResource.length() - 1);
            candidates.add("/" + singular);
            candidates.add("/" + singular + "-management");
        }

        // Convert to CandidatePage list
        for (String path : candidates) {
            String url = base + path;
            results.add(new CandidatePage(url, "medium",
                    "RESTful path inference from '" + apiPath + "'"));
        }

        logger.info("[PageLocator] Level 3 推断: %s → %d 个候选页面", apiPath, results.size());
        return results;
    }

    // ======================== Helpers ========================

    private String shortScriptName(String url) {
        int lastSlash = url.lastIndexOf('/');
        return lastSlash >= 0 ? url.substring(lastSlash + 1) : url;
    }

    private String jsString(String s) {
        return "'" + s.replace("\\", "\\\\").replace("'", "\\'") + "'";
    }

    // ======================== Data Types ========================

    /**
     * A candidate frontend page that may invoke the target API.
     *
     * @param url        the full page URL
     * @param confidence "high" (JS bundle match), "medium" (crawl/inference), "low" (fallback)
     * @param reason     human-readable explanation of why this page was selected
     */
    public record CandidatePage(String url, String confidence, String reason) {}
}
