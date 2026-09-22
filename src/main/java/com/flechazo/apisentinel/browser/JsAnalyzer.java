package com.flechazo.apisentinel.browser;

import com.flechazo.apisentinel.logging.LeveledLogger;
import com.microsoft.playwright.Page;

import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Analyzes JavaScript bundles for security-sensitive content.
 *
 * <p>Detects:
 * <ul>
 *   <li>API keys and secrets (AWS, Google, Stripe, etc.)</li>
 *   <li>Internal/private URLs (10.x, 172.16-31.x, 192.168.x, .internal, .local)</li>
 *   <li>Hardcoded API endpoints not in the API table</li>
 *   <li>Source map references (information disclosure)</li>
 *   <li>Dangerous JS sinks (innerHTML, document.write, eval, etc.)</li>
 * </ul>
 */
public class JsAnalyzer {

    /** Patterns for common API key formats. */
    private static final List<Pattern> SECRET_PATTERNS = List.of(
            // AWS
            Pattern.compile("AKIA[0-9A-Z]{16}"),
            // Google API key
            Pattern.compile("AIza[0-9A-Za-z_-]{35}"),
            // Stripe
            Pattern.compile("[rs]k_live_[0-9a-zA-Z]{24}"),
            // Generic API key assignments
            Pattern.compile("(?i)(api[_-]?key|apikey|api[_-]?secret)\\s*[:=]\\s*['\"][^'\"]{16,}['\"]"),
            // Bearer tokens
            Pattern.compile("bearer\\s+[a-zA-Z0-9._-]{20,}"),
            // JWT tokens
            Pattern.compile("eyJ[a-zA-Z0-9_-]+\\.eyJ[a-zA-Z0-9_-]+\\.[a-zA-Z0-9_-]+")
    );

    /** Patterns for internal/private URLs. */
    private static final List<Pattern> INTERNAL_URL_PATTERNS = List.of(
            Pattern.compile("https?://10\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}"),
            Pattern.compile("https?://172\\.(1[6-9]|2[0-9]|3[01])\\.\\d{1,3}\\.\\d{1,3}"),
            Pattern.compile("https?://192\\.168\\.\\d{1,3}\\.\\d{1,3}"),
            Pattern.compile("https?://[a-z0-9-]+\\.(internal|local|corp|intranet)"),
            Pattern.compile("https?://localhost:\\d+")
    );

    /** Patterns for hardcoded API endpoints. */
    private static final Pattern API_ENDPOINT_PATTERN = Pattern.compile(
            "['\"](/api/[a-zA-Z0-9_/-]+|/v[0-9]+/[a-zA-Z0-9_/-]+)['\"]"
    );

    /** Patterns for dangerous JS sinks (potential DOM XSS). */
    private static final List<Pattern> XSS_SINK_PATTERNS = List.of(
            Pattern.compile("\\.innerHTML\\s*="),
            Pattern.compile("\\.outerHTML\\s*="),
            Pattern.compile("document\\.write\\s*\\("),
            Pattern.compile("document\\.writeln\\s*\\("),
            Pattern.compile("\\beval\\s*\\("),
            Pattern.compile("\\bsetTimeout\\s*\\([^,)]*\\+"),
            Pattern.compile("\\bsetInterval\\s*\\([^,)]*\\+"),
            Pattern.compile("new\\s+Function\\s*\\("),
            Pattern.compile("\\.insertAdjacentHTML\\s*\\(")
    );

    /** Pattern for source map references. */
    private static final Pattern SOURCE_MAP_PATTERN = Pattern.compile(
            "//#\\s*sourceMappingURL\\s*=\\s*(.+?)(?:\\s|$)"
    );

    private final LeveledLogger logger;

    public JsAnalyzer(LeveledLogger logger) {
        this.logger = logger;
    }

    /**
     * Result of JS bundle analysis.
     */
    public record JsAnalysisResult(
            List<SecretFinding> secrets,
            List<String> internalUrls,
            List<DiscoveredApi> apiEndpoints,
            List<String> xssSinks,
            List<String> sourceMaps,
            int scriptsAnalyzed
    ) {
        public boolean hasFindings() {
            return !secrets.isEmpty() || !internalUrls.isEmpty() || !xssSinks.isEmpty();
        }
    }

    /**
     * A secret/key found in JS code.
     */
    public record SecretFinding(String type, String value, String context) {}

    /**
     * Analyze JavaScript content from a page.
     *
     * @param page the Playwright page
     * @param scriptUrls list of script URLs to fetch and analyze
     * @return analysis results
     */
    public JsAnalysisResult analyze(Page page, List<String> scriptUrls) {
        List<SecretFinding> secrets = new ArrayList<>();
        List<String> internalUrls = new ArrayList<>();
        List<DiscoveredApi> apiEndpoints = new ArrayList<>();
        List<String> xssSinks = new ArrayList<>();
        List<String> sourceMaps = new ArrayList<>();

        int scriptsAnalyzed = 0;

        // Analyze inline scripts from the page
        try {
            Object inlineScripts = page.evaluate("""
                (() => {
                    return Array.from(document.querySelectorAll('script:not([src])'))
                        .map(s => s.textContent)
                        .filter(t => t && t.length > 0);
                })()
                """);
            if (inlineScripts instanceof List<?> list) {
                for (Object script : list) {
                    if (script instanceof String content) {
                        analyzeContent(content, page.url(), secrets, internalUrls, apiEndpoints, xssSinks, sourceMaps);
                        scriptsAnalyzed++;
                    }
                }
            }
        } catch (Exception e) {
            logger.warn("[JsAnalyzer] 获取内联脚本失败: %s", e.getMessage());
        }

        // Analyze external scripts (fetch their content)
        for (String scriptUrl : scriptUrls) {
            try {
                Object content = page.evaluate("""
                    async (url) => {
                        try {
                            const response = await fetch(url);
                            return await response.text();
                        } catch (e) {
                            return null;
                        }
                    }
                    """, scriptUrl);
                if (content instanceof String jsContent) {
                    analyzeContent(jsContent, scriptUrl, secrets, internalUrls, apiEndpoints, xssSinks, sourceMaps);
                    scriptsAnalyzed++;
                }
            } catch (Exception e) {
                logger.warn("[JsAnalyzer] 获取脚本失败 %s: %s", scriptUrl, e.getMessage());
            }
        }

        logger.info("[JsAnalyzer] 分析了 %d 个脚本，发现 %d 个密钥, %d 个内部URL, %d 个XSS sink",
                scriptsAnalyzed, secrets.size(), internalUrls.size(), xssSinks.size());

        return new JsAnalysisResult(secrets, internalUrls, apiEndpoints, xssSinks, sourceMaps, scriptsAnalyzed);
    }

    /**
     * Analyze a single JS content string.
     */
    private void analyzeContent(String content, String source,
                                List<SecretFinding> secrets,
                                List<String> internalUrls,
                                List<DiscoveredApi> apiEndpoints,
                                List<String> xssSinks,
                                List<String> sourceMaps) {
        if (content == null || content.isEmpty()) return;

        // Check for secrets
        for (Pattern pattern : SECRET_PATTERNS) {
            Matcher matcher = pattern.matcher(content);
            while (matcher.find()) {
                String match = matcher.group();
                if (match.length() > 100) match = match.substring(0, 100) + "...";
                secrets.add(new SecretFinding("api_key", match, source));
            }
        }

        // Check for internal URLs
        for (Pattern pattern : INTERNAL_URL_PATTERNS) {
            Matcher matcher = pattern.matcher(content);
            while (matcher.find()) {
                String url = matcher.group();
                if (!internalUrls.contains(url)) {
                    internalUrls.add(url);
                }
            }
        }

        // Check for hardcoded API endpoints
        Matcher apiMatcher = API_ENDPOINT_PATTERN.matcher(content);
        Set<String> seenPaths = new HashSet<>();
        while (apiMatcher.find()) {
            String path = apiMatcher.group(1);
            if (seenPaths.add(path)) {
                apiEndpoints.add(DiscoveredApi.fromJsBundle("GET", path, source));
            }
        }

        // Check for XSS sinks
        for (Pattern pattern : XSS_SINK_PATTERNS) {
            Matcher matcher = pattern.matcher(content);
            while (matcher.find()) {
                String sink = matcher.group();
                int lineNum = getLineNumber(content, matcher.start());
                String sinkInfo = sink + " (line " + lineNum + ")";
                if (!xssSinks.contains(sinkInfo)) {
                    xssSinks.add(sinkInfo);
                }
            }
        }

        // Check for source maps
        Matcher smMatcher = SOURCE_MAP_PATTERN.matcher(content);
        while (smMatcher.find()) {
            String mapUrl = smMatcher.group(1).trim();
            if (!sourceMaps.contains(mapUrl)) {
                sourceMaps.add(mapUrl);
            }
        }
    }

    /**
     * Get line number for a character position.
     */
    private int getLineNumber(String content, int position) {
        int line = 1;
        for (int i = 0; i < position && i < content.length(); i++) {
            if (content.charAt(i) == '\n') line++;
        }
        return line;
    }
}
