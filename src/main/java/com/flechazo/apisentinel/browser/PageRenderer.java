package com.flechazo.apisentinel.browser;

import com.flechazo.apisentinel.logging.LeveledLogger;
import com.microsoft.playwright.*;
import com.microsoft.playwright.options.WaitUntilState;

import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;

/**
 * Renders web pages and extracts DOM, console logs, and other runtime information.
 *
 * <p>Provides methods to navigate to URLs, wait for elements, and extract
 * page content for security analysis.
 */
public class PageRenderer {

    private static final int DEFAULT_TIMEOUT_MS = 30000;
    private static final int MAX_DOM_LENGTH = 50000;

    private final Page page;
    private final LeveledLogger logger;
    private final List<String> consoleLogs = new ArrayList<>();
    private final List<String> cspViolations = new ArrayList<>();

    public PageRenderer(Page page, LeveledLogger logger) {
        this.page = page;
        this.logger = logger;

        // Capture console messages
        page.onConsoleMessage(msg -> {
            String logEntry = String.format("[%s] %s", msg.type(), msg.text());
            consoleLogs.add(logEntry);
            // Limit console log size
            if (consoleLogs.size() > 500) {
                consoleLogs.remove(0);
            }
        });

        // Capture CSP violations via page errors
        page.onPageError(error -> {
            if (error.contains("Content Security Policy") || error.contains("CSP")) {
                cspViolations.add(error);
            }
        });
    }

    /**
     * Navigate to a URL and wait for the page to load.
     *
     * @param url the URL to navigate to
     * @param timeoutMs maximum wait time in milliseconds
     * @return true if navigation succeeded, false if timeout/error
     */
    public boolean navigate(String url, int timeoutMs) {
        try {
            page.navigate(url, new Page.NavigateOptions()
                    .setTimeout(timeoutMs > 0 ? timeoutMs : DEFAULT_TIMEOUT_MS)
                    .setWaitUntil(WaitUntilState.NETWORKIDLE));
            return true;
        } catch (Exception e) {
            logger.warn("[PageRenderer] 导航失败 %s: %s", url, e.getMessage());
            return false;
        }
    }

    /**
     * Navigate with default timeout.
     */
    public boolean navigate(String url) {
        return navigate(url, DEFAULT_TIMEOUT_MS);
    }

    /**
     * Get the rendered DOM (after JS execution).
     *
     * @return the full HTML content, truncated if too long
     */
    public String getRenderedDom() {
        try {
            String html = page.content();
            if (html.length() > MAX_DOM_LENGTH) {
                return html.substring(0, MAX_DOM_LENGTH) + "\n<!-- TRUNCATED -->";
            }
            return html;
        } catch (Exception e) {
            return "<!-- Error getting DOM: " + e.getMessage() + " -->";
        }
    }

    /**
     * Get the page title.
     */
    public String getTitle() {
        try {
            return page.title();
        } catch (Exception e) {
            return "";
        }
    }

    /**
     * Get the current URL.
     */
    public String getCurrentUrl() {
        try {
            return page.url();
        } catch (Exception e) {
            return "";
        }
    }

    /**
     * Get captured console logs.
     */
    public List<String> getConsoleLogs() {
        return new ArrayList<>(consoleLogs);
    }

    /**
     * Get captured CSP violations.
     */
    public List<String> getCspViolations() {
        return new ArrayList<>(cspViolations);
    }

    /**
     * Take a screenshot and return as base64-encoded PNG.
     */
    public String screenshot() {
        try {
            byte[] bytes = page.screenshot();
            return Base64.getEncoder().encodeToString(bytes);
        } catch (Exception e) {
            logger.warn("[PageRenderer] 截图失败: %s", e.getMessage());
            return "";
        }
    }

    /**
     * Click an element matching the selector.
     *
     * @param selector CSS or XPath selector
     * @return true if click succeeded
     */
    public boolean click(String selector) {
        try {
            page.click(selector, new Page.ClickOptions().setTimeout(5000));
            return true;
        } catch (Exception e) {
            logger.warn("[PageRenderer] 点击失败 %s: %s", selector, e.getMessage());
            return false;
        }
    }

    /**
     * Fill a form input with a value.
     *
     * @param selector CSS or XPath selector for the input
     * @param value the value to fill
     * @return true if fill succeeded
     */
    public boolean fill(String selector, String value) {
        try {
            page.fill(selector, value, new Page.FillOptions().setTimeout(5000));
            return true;
        } catch (Exception e) {
            logger.warn("[PageRenderer] 填充失败 %s: %s", selector, e.getMessage());
            return false;
        }
    }

    /**
     * Select an option from a &lt;select&gt; dropdown.
     *
     * @param selector CSS or XPath selector for the select element
     * @param value the option value to select
     * @return true if selection succeeded
     */
    public boolean select(String selector, String value) {
        try {
            page.selectOption(selector, value, new Page.SelectOptionOptions().setTimeout(5000));
            return true;
        } catch (Exception e) {
            logger.warn("[PageRenderer] 选择失败 %s: %s", selector, e.getMessage());
            return false;
        }
    }

    /**
     * Check (tick) a checkbox.
     *
     * @param selector CSS or XPath selector for the checkbox
     * @return true if check succeeded
     */
    public boolean check(String selector) {
        try {
            page.check(selector, new Page.CheckOptions().setTimeout(5000));
            return true;
        } catch (Exception e) {
            logger.warn("[PageRenderer] 勾选失败 %s: %s", selector, e.getMessage());
            return false;
        }
    }

    /**
     * Type text character-by-character (simulates real keyboard input).
     *
     * @param selector CSS or XPath selector for the input
     * @param value the text to type
     * @param delayMs delay between keystrokes (0 = instant)
     * @return true if typing succeeded
     */
    public boolean type(String selector, String value, int delayMs) {
        try {
            page.type(selector, value, new Page.TypeOptions()
                    .setDelay(delayMs > 0 ? delayMs : 0)
                    .setTimeout(5000));
            return true;
        } catch (Exception e) {
            logger.warn("[PageRenderer] 输入失败 %s: %s", selector, e.getMessage());
            return false;
        }
    }

    /**
     * Wait for a network request matching the URL pattern.
     *
     * <p>Returns a {@link CapturedRequest} with full request/response details,
     * or null if no matching request was observed within the timeout.
     *
     * @param urlPattern glob pattern (e.g. "*&#47;api/v1/orders*")
     * @param timeoutMs maximum wait time in milliseconds
    /**
     * Hover over an element (triggers CSS :hover dropdowns, tooltips, etc.).
     */
    public boolean hover(String selector) {
        try {
            ElementHandle el = page.querySelector(selector);
            if (el == null) return false;
            el.hover();
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Scroll to an element, or scroll the page by a direction.
     * @param selector element selector, or null to scroll the whole page
     * @param direction "top", "bottom", or a pixel number (e.g. "500")
     */
    public boolean scrollTo(String selector, String direction) {
        try {
            if (selector != null && !selector.isEmpty()) {
                ElementHandle el = page.querySelector(selector);
                if (el != null) {
                    el.scrollIntoViewIfNeeded();
                    return true;
                }
                return false;
            }
            String dir = direction != null ? direction.toLowerCase() : "bottom";
            int scrollAmount = switch (dir) {
                case "top" -> 0;
                case "bottom" -> (int) page.evaluate("document.body.scrollHeight");
                default -> {
                    try { yield Integer.parseInt(dir); }
                    catch (NumberFormatException e) { yield 500; }
                }
            };
            page.evaluate("window.scrollTo(0, " + scrollAmount + ")");
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Upload a file to a file input element.
     * @param selector CSS selector for the input[type=file] element
     * @param filePath local file path
     */
    public boolean uploadFile(String selector, String filePath) {
        try {
            ElementHandle el = page.querySelector(selector);
            if (el == null) return false;
            el.setInputFiles(java.nio.file.Path.of(filePath));
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Press a keyboard key (Enter, Tab, Escape, etc.).
     * If selector is provided, focuses the element first.
     * @param selector element to focus, or null to press on the page
     * @param key key name (e.g. "Enter", "Tab", "Escape", "ArrowDown")
     */
    public boolean pressKey(String selector, String key) {
        try {
            if (selector != null && !selector.isEmpty()) {
                ElementHandle el = page.querySelector(selector);
                if (el != null) el.press(key);
            } else {
                page.keyboard().press(key);
            }
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * @return captured request details, or null on timeout
     */
    public CapturedRequest waitForRequest(String urlPattern, int timeoutMs) {
        try {
            // Convert glob to regex for Predicate-based matching
            String regexStr = ".*" + urlPattern.replace("*", ".*")
                    .replace("?", ".") + ".*";
            java.util.regex.Pattern pattern = java.util.regex.Pattern.compile(regexStr);

            int timeout = timeoutMs > 0 ? timeoutMs : 10000;

            // Playwright's waitForRequest(predicate, runnable) runs the runnable
            // and waits for a request matching the predicate. We pass an empty
            // runnable since the triggering action happens externally (e.g. via
            // browser_interact click/fill actions that already executed).
            com.microsoft.playwright.Request req = page.waitForRequest(
                    (java.util.function.Predicate<com.microsoft.playwright.Request>)
                            r -> pattern.matcher(r.url()).matches(),
                    () -> { /* no-op: trigger already happened */ });

            if (req == null) return null;

            Map<String, String> headers = req.headers();
            String body = req.postData() != null ? req.postData() : "";

            // Try to get the response (may not be available yet)
            int responseStatus = 0;
            String responseBodySnippet = "";
            try {
                com.microsoft.playwright.Response resp = req.response();
                if (resp != null) {
                    responseStatus = resp.status();
                    byte[] respBody = resp.body();
                    if (respBody != null) {
                        String respStr = new String(respBody);
                        responseBodySnippet = respStr.length() > 500
                                ? respStr.substring(0, 500) + "..." : respStr;
                    }
                }
            } catch (Exception ignored) {
                // Response may not be available
            }

            return new CapturedRequest(
                    req.method(), req.url(), headers, body,
                    responseStatus, responseBodySnippet);

        } catch (Exception e) {
            logger.debug("[PageRenderer] 等待请求超时 %s: %s", urlPattern, e.getMessage());
            return null;
        }
    }

    /**
     * Extract all form fields from the page for Agent guidance.
     *
     * @return list of form field descriptors
     */
    public List<FormFieldInfo> extractFormFields() {
        List<FormFieldInfo> fields = new ArrayList<>();
        try {
            Object result = page.evaluate("""
                (() => {
                    const fields = [];
                    const inputs = document.querySelectorAll('input, select, textarea');
                    for (const el of inputs) {
                        const info = {
                            tagName: el.tagName.toLowerCase(),
                            type: el.type || '',
                            name: el.name || '',
                            id: el.id || '',
                            placeholder: el.placeholder || '',
                            required: el.required || false,
                            options: []
                        };
                        if (el.tagName.toLowerCase() === 'select') {
                            for (const opt of el.options) {
                                info.options.push(opt.value);
                            }
                        }
                        // Skip hidden inputs
                        if (el.type === 'hidden') continue;
                        fields.push(info);
                        if (fields.length >= 50) break;
                    }
                    return fields;
                })()
                """);

            if (result instanceof List<?> list) {
                for (Object item : list) {
                    if (item instanceof Map<?, ?> map) {
                        fields.add(new FormFieldInfo(
                                str(map, "tagName"),
                                str(map, "type"),
                                str(map, "name"),
                                str(map, "id"),
                                str(map, "placeholder"),
                                Boolean.TRUE.equals(map.get("required")),
                                extractStringList(map.get("options"))
                        ));
                    }
                }
            }
        } catch (Exception e) {
            logger.warn("[PageRenderer] 提取表单字段失败: %s", e.getMessage());
        }
        return fields;
    }

    private static String str(Map<?, ?> map, String key) {
        Object v = map.get(key);
        return v instanceof String s ? s : "";
    }

    private static List<String> extractStringList(Object obj) {
        List<String> result = new ArrayList<>();
        if (obj instanceof List<?> list) {
            for (Object item : list) {
                if (item instanceof String s) result.add(s);
            }
        }
        return result;
    }

    /**
     * Wait for an element to appear.
     *
     * @param selector CSS or XPath selector
     * @param timeoutMs maximum wait time
     * @return true if element appeared
     */
    public boolean waitForSelector(String selector, int timeoutMs) {
        try {
            page.waitForSelector(selector, new Page.WaitForSelectorOptions()
                    .setTimeout(timeoutMs > 0 ? timeoutMs : 10000));
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Execute JavaScript in the page context.
     *
     * @param expression JavaScript expression to evaluate
     * @return the result (may be null)
     */
    public Object evaluate(String expression) {
        try {
            return page.evaluate(expression);
        } catch (Exception e) {
            logger.warn("[PageRenderer] JS 执行失败: %s", e.getMessage());
            return null;
        }
    }

    /**
     * Extract frontend routes from the page (Vue Router, React Router, etc.)
     *
     * @return list of discovered route paths
     */
    public List<String> extractFrontendRoutes() {
        List<String> routes = new ArrayList<>();

        // Try Vue Router
        try {
            Object vueRoutes = page.evaluate("""
                (() => {
                    const app = document.querySelector('#app')?.__vue_app__;
                    if (app && app.config.globalProperties.$router) {
                        return app.config.globalProperties.$router.options.routes
                            .map(r => r.path)
                            .filter(p => p && !p.startsWith(':'));
                    }
                    return [];
                })()
                """);
            if (vueRoutes instanceof List<?> list) {
                for (Object r : list) {
                    if (r instanceof String s) routes.add(s);
                }
            }
        } catch (Exception ignored) {}

        // Try React Router (look for links with href)
        try {
            Object reactLinks = page.evaluate("""
                (() => {
                    const links = document.querySelectorAll('a[href]');
                    const paths = new Set();
                    links.forEach(l => {
                        const href = l.getAttribute('href');
                        if (href && href.startsWith('/') && !href.includes('//')) {
                            paths.add(href.split('?')[0]);
                        }
                    });
                    return Array.from(paths);
                })()
                """);
            if (reactLinks instanceof List<?> list) {
                for (Object r : list) {
                    if (r instanceof String s && !routes.contains(s)) routes.add(s);
                }
            }
        } catch (Exception ignored) {}

        return routes;
    }

    /**
     * Extract all script src URLs from the page.
     *
     * @return list of script URLs
     */
    public List<String> getScriptUrls() {
        List<String> urls = new ArrayList<>();
        try {
            Object scripts = page.evaluate("""
                (() => {
                    return Array.from(document.querySelectorAll('script[src]'))
                        .map(s => s.src);
                })()
                """);
            if (scripts instanceof List<?> list) {
                for (Object s : list) {
                    if (s instanceof String str) urls.add(str);
                }
            }
        } catch (Exception ignored) {}
        return urls;
    }

    /**
     * Close the page.
     */
    public void close() {
        try {
            page.close();
        } catch (Exception ignored) {}
    }

    /**
     * Get the underlying Playwright Page for advanced operations.
     */
    public Page getPage() {
        return page;
    }
}
