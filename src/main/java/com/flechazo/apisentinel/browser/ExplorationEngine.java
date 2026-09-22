package com.flechazo.apisentinel.browser;

import com.flechazo.apisentinel.ai.provider.ChatMessage;
import com.flechazo.apisentinel.ai.provider.LlmProvider;
import com.flechazo.apisentinel.ai.provider.LlmRequest;
import com.flechazo.apisentinel.ai.provider.LlmResponse;
import com.flechazo.apisentinel.browser.BrowserService.BrowserAction;
import com.flechazo.apisentinel.browser.DomSimplifier.InteractiveElement;
import com.flechazo.apisentinel.logging.LeveledLogger;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.microsoft.playwright.ElementHandle;
import com.microsoft.playwright.Page;
import com.microsoft.playwright.options.LoadState;

import java.util.*;

/**
 * Intelligent exploration engine for triggering target APIs through browser navigation.
 *
 * <p>Given a target API endpoint, this engine automatically navigates through
 * a web application's UI (clicking menus, tabs, buttons, filling forms) until
 * it triggers the target API. Uses an LLM to make navigation decisions based
 * on the current page's interactive elements.
 *
 * <p>Key features:
 * <ul>
 *   <li>LLM-powered decision making for navigation</li>
 *   <li>Loop detection and backtracking</li>
 *   <li>Cached exploration paths for reuse</li>
 *   <li>Configurable max depth and hints</li>
 * </ul>
 *
 * <p>Usage:
 * <pre>
 * ExplorationEngine engine = new ExplorationEngine(logger, browserManager, llmProvider);
 * ExploreResult result = engine.explore("http://app.example.com", "POST /api/v1/roles", 10, List.of());
 * if (result.success()) {
 *     // Use result.actionSequence() and result.capturedRequest()
 * }
 * </pre>
 */
public class ExplorationEngine {

    private final LeveledLogger logger;
    private final BrowserManager browserManager;
    private final LlmProvider llmProvider;
    private final DomSimplifier domSimplifier;
    private final NetworkMonitor networkMonitor;
    private final ExplorationCache cache;

    /** Default max exploration depth. */
    private static final int DEFAULT_MAX_DEPTH = 10;

    /** Wait time after each action for page to settle. */
    private static final int ACTION_SETTLE_MS = 1500;

    /** Wait time for network request after triggering action. */
    private static final int REQUEST_WAIT_MS = 5000;

    /** Whether to use vision (screenshots) for LLM decisions. */
    private volatile boolean useVision = true;

    /** Vision model name override (null = use provider default). */
    private volatile String visionModelOverride = null;

    public ExplorationEngine(LeveledLogger logger, BrowserManager browserManager, LlmProvider llmProvider) {
        this.logger = logger;
        this.browserManager = browserManager;
        this.llmProvider = llmProvider;
        this.domSimplifier = new DomSimplifier(logger);
        this.networkMonitor = new NetworkMonitor(logger);
        this.cache = new ExplorationCache(logger);
    }

    /**
     * Enable or disable vision-based decisions.
     * When enabled, screenshots are sent to the LLM for better navigation understanding.
     */
    public void setUseVision(boolean useVision) {
        this.useVision = useVision;
    }

    /**
     * Set a vision model override for LLM decisions.
     * If null, uses the provider's default model.
     */
    public void setVisionModelOverride(String model) {
        this.visionModelOverride = model;
    }

    /**
     * Explore the application to trigger a target API.
     *
     * @param startUrl  starting URL (usually app homepage or known entry point)
     * @param targetApi target API to trigger (e.g., "POST /api/v1/roles")
     * @param maxDepth  maximum exploration depth (0 = use default)
     * @param hints     optional hints to guide exploration (e.g., ["在权限管理菜单下"])
     * @return exploration result
     */
    public ExploreResult explore(String startUrl, String targetApi, int maxDepth, List<String> hints) {
        if (startUrl == null || startUrl.isEmpty()) {
            return ExploreResult.failure("startUrl is required");
        }
        if (targetApi == null || targetApi.isEmpty()) {
            return ExploreResult.failure("targetApi is required");
        }

        int depth = maxDepth > 0 ? maxDepth : DEFAULT_MAX_DEPTH;
        logger.debug("[ExplorationEngine] 开始探索: %s → %s (max_depth=%d)", startUrl, targetApi, depth);

        // Check cache first
        List<BrowserAction> cachedActions = cache.get(targetApi);
        if (cachedActions != null) {
            logger.debug("[ExplorationEngine] 缓存命中，尝试回放");
            ExploreResult replayResult = replayActions(startUrl, targetApi, cachedActions);
            if (replayResult.success()) {
                return replayResult;
            }
            logger.info("[ExplorationEngine] 缓存回放失败，重新探索");
        }

        Page page = null;
        try {
            page = browserManager.getSharedPage();
            this.currentPage = page;  // Set for screenshot capture in llmDecide

            // Navigate to start URL
            page.navigate(startUrl);
            page.waitForLoadState(LoadState.NETWORKIDLE);

            // Start monitoring network
            networkMonitor.startMonitoring(page);

            List<BrowserAction> actionSequence = new ArrayList<>();
            Set<String> visitedStates = new HashSet<>();  // URL + DOM hash for loop detection
            List<String> actionHistory = new ArrayList<>();  // Human-readable history for LLM

            for (int step = 0; step < depth; step++) {
                logger.debug("[ExplorationEngine] Step %d/%d: %s", step + 1, depth, page.url());

                // Check if target API was triggered
                if (hasCapturedTarget(targetApi)) {
                    CapturedRequest captured = getCapturedRequest(targetApi, page);
                    cache.put(targetApi, actionSequence);
                    logger.debug("[ExplorationEngine] 成功触发 %s (共 %d 步)", targetApi, actionSequence.size());
                    return ExploreResult.success(actionSequence, captured, actionHistory);
                }

                // Get current state for loop detection
                String stateKey = getStateKey(page);
                if (visitedStates.contains(stateKey)) {
                    logger.debug("[ExplorationEngine] 检测到循环，尝试回退");
                    if (!backtrack(page, actionSequence, actionHistory)) {
                        return ExploreResult.failure("陷入循环且无法回退");
                    }
                    continue;
                }
                visitedStates.add(stateKey);

                // Extract interactive elements
                List<InteractiveElement> elements = domSimplifier.extract(page);
                if (elements.isEmpty()) {
                    logger.warn("[ExplorationEngine] 页面无可见可交互元素");
                    if (!backtrack(page, actionSequence, actionHistory)) {
                        return ExploreResult.failure("页面无可见可交互元素且无法回退");
                    }
                    continue;
                }

                // LLM decision
                BrowserAction nextAction = llmDecide(targetApi, page.url(), elements, actionHistory, hints);
                if (nextAction == null) {
                    // LLM couldn't decide or suggested giving up
                    if (!backtrack(page, actionSequence, actionHistory)) {
                        return ExploreResult.failure("LLM 无法决定下一步且无法回退");
                    }
                    continue;
                }

                // Execute action — snapshot elements before for diff
                List<InteractiveElement> elementsBefore = elements;
                if (!executeAction(page, nextAction)) {
                    logger.warn("[ExplorationEngine] 动作执行失败: %s %s", nextAction.type(), nextAction.selector());
                    continue;
                }

                actionSequence.add(nextAction);

                // Smart wait: prefer NETWORKIDLE, fall back to short timeout
                try {
                    page.waitForLoadState(com.microsoft.playwright.options.LoadState.NETWORKIDLE,
                            new Page.WaitForLoadStateOptions().setTimeout(3000));
                } catch (Exception ignored) {
                    page.waitForTimeout(500);
                }

                // DOM diff: analyze what changed after the action
                List<InteractiveElement> elementsAfter = domSimplifier.extract(page);
                String diffSummary = computeDomDiff(elementsBefore, elementsAfter);
                actionHistory.add(formatAction(nextAction) + (diffSummary.isEmpty() ? "" : " → " + diffSummary));
            }

            // Final check after all steps
            if (hasCapturedTarget(targetApi)) {
                CapturedRequest captured = getCapturedRequest(targetApi, page);
                cache.put(targetApi, actionSequence);
                return ExploreResult.success(actionSequence, captured, actionHistory);
            }

            return ExploreResult.failure("超过最大深度 " + depth + " 未触发目标 API");

        } catch (Exception e) {
            logger.error("[ExplorationEngine] 探索异常: %s", e.getMessage());
            return ExploreResult.failure("探索异常: " + e.getMessage());
        } finally {
            networkMonitor.stopMonitoring();
            this.currentPage = null;  // Clear page reference
            // Don't close the shared page — it's reused across tool calls
            if (page != null && !browserManager.isSharedPage(page)) {
                try { page.close(); } catch (Exception ignored) {}
            }
        }
    }

    /**
     * Replay a cached action sequence.
     */
    private ExploreResult replayActions(String startUrl, String targetApi, List<BrowserAction> actions) {
        Page page = null;
        try {
            page = browserManager.getSharedPage();
            page.navigate(startUrl);
            page.waitForLoadState(LoadState.NETWORKIDLE);

            networkMonitor.startMonitoring(page);

            List<String> history = new ArrayList<>();
            for (BrowserAction action : actions) {
                if (!executeAction(page, action)) {
                    return ExploreResult.failure("回放动作失败: " + formatAction(action));
                }
                history.add(formatAction(action));
                page.waitForTimeout(ACTION_SETTLE_MS);
            }

            // Check if target was triggered
            if (hasCapturedTarget(targetApi)) {
                CapturedRequest captured = getCapturedRequest(targetApi, page);
                return ExploreResult.success(actions, captured, history);
            }

            return ExploreResult.failure("回放完成但未触发目标 API");
        } catch (Exception e) {
            return ExploreResult.failure("回放异常: " + e.getMessage());
        } finally {
            networkMonitor.stopMonitoring();
            // Don't close the shared page — it's reused across tool calls
            if (page != null && !browserManager.isSharedPage(page)) {
                try { page.close(); } catch (Exception ignored) {}
            }
        }
    }

    /**
     * Use LLM to decide the next action.
     * When vision is enabled, sends a screenshot along with the DOM analysis.
     */
    private BrowserAction llmDecide(String targetApi, String currentUrl,
                                     List<InteractiveElement> elements,
                                     List<String> actionHistory,
                                     List<String> hints) {
        String textPrompt = buildDecisionPrompt(targetApi, currentUrl, elements, actionHistory, hints);

        try {
            // Check if vision is enabled and we have a page to screenshot
            String screenshot = null;
            if (useVision && !elements.isEmpty()) {
                try {
                    // Take screenshot of the current page via DOM simplifier's page
                    screenshot = captureScreenshot();
                } catch (Exception e) {
                    logger.debug("[ExplorationEngine] 截图失败，回退到纯文本: %s", e.getMessage());
                }
            }

            LlmRequest request;
            if (screenshot != null && !screenshot.isEmpty()) {
                // Vision mode: send screenshot + text as multimodal message
                ChatMessage systemMsg = ChatMessage.system(
                        "你是一个浏览器自动化助手，帮助用户在页面上导航以触发目标 API。"
                        + "你同时可以看到页面截图，结合截图和 DOM 元素做出更准确的决策。"
                        + "请以 JSON 格式返回决策。");
                ChatMessage userMsg = ChatMessage.userWithImage(textPrompt, screenshot, "image/png");

                request = new LlmRequest(
                        List.of(systemMsg, userMsg),
                        null,  // no tools
                        0.1,   // low temperature
                        1024
                );
                // Apply vision model override if set
                if (visionModelOverride != null && !visionModelOverride.isBlank()) {
                    request = request.withModelOverride(visionModelOverride);
                }
                logger.debug("[ExplorationEngine] 使用视觉模式决策 (screenshot=%d bytes)", screenshot.length());
            } else {
                // Text-only mode
                request = new LlmRequest(
                        "你是一个浏览器自动化助手，帮助用户在页面上导航以触发目标 API。请以 JSON 格式返回决策。",
                        textPrompt,
                        0.1,  // low temperature for consistent decisions
                        1024,
                        "json"
                );
            }

            LlmResponse response = llmProvider.complete(request).get();
            if (response == null || response.content() == null) {
                logger.warn("[ExplorationEngine] LLM 返回空响应");
                return null;
            }

            return parseActionResponse(response.content());
        } catch (Exception e) {
            logger.warn("[ExplorationEngine] LLM 决策失败: %s", e.getMessage());
            return null;
        }
    }

    /** Current page reference for screenshot capture (set during explore loop). */
    private volatile com.microsoft.playwright.Page currentPage;

    /**
     * Capture a screenshot of the current page.
     */
    private String captureScreenshot() {
        if (currentPage == null) return null;
        try {
            byte[] bytes = currentPage.screenshot();
            return java.util.Base64.getEncoder().encodeToString(bytes);
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Build the LLM prompt for decision making.
     */
    private String buildDecisionPrompt(String targetApi, String currentUrl,
                                        List<InteractiveElement> elements,
                                        List<String> actionHistory,
                                        List<String> hints) {
        StringBuilder sb = new StringBuilder();

        sb.append("你是一个浏览器自动化助手，目标是通过页面操作触发 API: ").append(targetApi).append("\n\n");

        sb.append("当前状态:\n");
        sb.append("- URL: ").append(currentUrl).append("\n");
        sb.append("- 已执行操作:\n");
        if (actionHistory.isEmpty()) {
            sb.append("  (无)\n");
        } else {
            for (String action : actionHistory) {
                sb.append("  - ").append(action).append("\n");
            }
        }
        sb.append("\n");

        if (hints != null && !hints.isEmpty()) {
            sb.append("提示:\n");
            for (String hint : hints) {
                sb.append("- ").append(hint).append("\n");
            }
            sb.append("\n");
        }

        sb.append("当前页面可交互元素:\n");
        sb.append(domSimplifier.formatForPrompt(elements));
        sb.append("\n");

        sb.append("""
            请分析并决定下一步操作。思考要点:
            1. 目标 API 的资源名是什么？(如 /api/v1/roles → 角色管理)
            2. 哪个菜单/按钮/标签最可能通向该功能？
            3. 如果当前路不通，考虑返回上一步
            
            返回 JSON 格式 (仅返回 JSON，不要其他内容):
            {
              "action": "click" | "fill" | "hover" | "back" | "giveup",
              "selector": "元素选择器 (click/fill/hover 时必填)",
              "value": "填写值 (仅 fill 时需要)",
              "reason": "为什么选择这个操作"
            }
            """);

        return sb.toString();
    }

    /**
     * Parse LLM response into a BrowserAction.
     */
    private BrowserAction parseActionResponse(String response) {
        try {
            // Extract JSON from response (might have markdown code blocks)
            String json = response.trim();
            if (json.startsWith("```")) {
                json = json.replaceAll("```json\\s*", "").replaceAll("```\\s*$", "").trim();
            }

            JsonObject obj = JsonParser.parseString(json).getAsJsonObject();
            String action = obj.has("action") ? obj.get("action").getAsString() : "";
            String reason = obj.has("reason") ? obj.get("reason").getAsString() : "";

            logger.debug("[ExplorationEngine] LLM 决策: %s (%s)", action, reason);

            return switch (action.toLowerCase()) {
                case "click" -> new BrowserAction("click",
                        getStr(obj, "selector"), null, 5000, null, 0);
                case "fill" -> new BrowserAction("fill",
                        getStr(obj, "selector"), getStr(obj, "value"), 5000, null, 0);
                case "hover" -> new BrowserAction("hover",
                        getStr(obj, "selector"), null, 5000, null, 0);
                case "back" -> new BrowserAction("back", null, null, 0, null, 0);
                case "giveup" -> null;  // Signal to backtrack
                default -> null;
            };
        } catch (Exception e) {
            logger.warn("[ExplorationEngine] 解析 LLM 响应失败: %s", e.getMessage());
            return null;
        }
    }

    /**
     * Execute a browser action.
     */
    private boolean executeAction(Page page, BrowserAction action) {
        try {
            switch (action.type()) {
                case "click" -> {
                    page.click(action.selector());
                    return true;
                }
                case "fill" -> {
                    page.fill(action.selector(), action.value() != null ? action.value() : "");
                    return true;
                }
                case "hover" -> {
                    page.hover(action.selector());
                    return true;
                }
                case "back" -> {
                    page.goBack();
                    page.waitForLoadState(LoadState.NETWORKIDLE);
                    return true;
                }
                default -> {
                    logger.warn("[ExplorationEngine] 未知动作类型: %s", action.type());
                    return false;
                }
            }
        } catch (Exception e) {
            logger.warn("[ExplorationEngine] 动作执行失败: %s", e.getMessage());
            return false;
        }
    }

    /**
     * Check if the target API was captured.
     */
    private boolean hasCapturedTarget(String targetApi) {
        String[] parts = targetApi.split("\\s+", 2);
        String method = parts.length > 1 ? parts[0] : "GET";
        String path = parts.length > 1 ? parts[1] : parts[0];

        for (DiscoveredApi api : networkMonitor.getUniqueApis()) {
            if (api.path().contains(path) || path.contains(api.path())) {
                if (method.equalsIgnoreCase(api.method()) || "GET".equalsIgnoreCase(method)) {
                    return true;
                }
            }
        }
        return false;
    }

    /**
     * Get the captured request for the target API.
     */
    private CapturedRequest getCapturedRequest(String targetApi, Page page) {
        String[] parts = targetApi.split("\\s+", 2);
        String path = parts.length > 1 ? parts[1] : parts[0];

        for (DiscoveredApi api : networkMonitor.getUniqueApis()) {
            if (api.path().contains(path) || path.contains(api.path())) {
                return new CapturedRequest(
                        api.method(),
                        api.path(),
                        Map.of(),  // Headers not available from DiscoveredApi
                        api.requestBody(),
                        200,  // Status not available
                        api.responseSnippet()  // This is correct - DiscoveredApi has responseSnippet()
                );
            }
        }
        return null;
    }

    /**
     * Get a state key for loop detection (URL + simplified DOM hash).
     */
    private String getStateKey(Page page) {
        try {
            String url = page.url();
            // Use URL + visible text hash as state (DOM changes without navigation)
            String visibleText = (String) page.evaluate("document.body?.innerText?.substring(0, 500) || ''");
            return url + "|" + visibleText.hashCode();
        } catch (Exception e) {
            return page.url();
        }
    }

    /**
     * Backtrack by removing last action and going back.
     */
    private boolean backtrack(Page page, List<BrowserAction> actionSequence, List<String> history) {
        if (actionSequence.isEmpty()) return false;

        // Pop the last action and try to undo it in-place (preserves SPA state)
        BrowserAction last = actionSequence.remove(actionSequence.size() - 1);
        if (!history.isEmpty()) {
            history.remove(history.size() - 1);
        }

        // Action-specific undo (preserves SPA state, avoids full page reload)
        try {
            switch (last.type()) {
                case "click" -> {
                    // Toggle: click the same element again to undo (dropdowns, tabs, modals)
                    ElementHandle el = page.querySelector(last.selector());
                    if (el != null && el.isVisible()) {
                        el.click();
                        page.waitForTimeout(300);
                        return true;
                    }
                }
                case "fill", "type" -> {
                    // Clear the input we filled
                    ElementHandle el = page.querySelector(last.selector());
                    if (el != null) {
                        el.fill("");
                        return true;
                    }
                }
                case "scroll" -> {
                    page.evaluate("window.scrollTo(0, 0)");
                    return true;
                }
                case "check" -> {
                    ElementHandle el = page.querySelector(last.selector());
                    if (el != null) el.uncheck();
                    return true;
                }
            }
        } catch (Exception ignored) {}

        // Fallback: browser back (loses SPA state, but sometimes the only option)
        try {
            page.goBack(new Page.GoBackOptions().setTimeout(2000));
            page.waitForLoadState(LoadState.NETWORKIDLE,
                    new Page.WaitForLoadStateOptions().setTimeout(2000));
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Compute a human-readable summary of DOM changes between two element snapshots.
     * Helps the LLM understand what happened after an action.
     */
    private String computeDomDiff(List<InteractiveElement> before, List<InteractiveElement> after) {
        if (before == null || after == null) return "";
        if (before.isEmpty() && after.isEmpty()) return "";
        if (before.isEmpty()) return "页面加载了" + after.size() + "个可交互元素";

        java.util.Set<String> beforeSelectors = new java.util.HashSet<>();
        for (var el : before) beforeSelectors.add(el.selector());

        java.util.Set<String> afterSelectors = new java.util.HashSet<>();
        for (var el : after) afterSelectors.add(el.selector());

        // New elements (appeared after action)
        java.util.List<String> added = new java.util.ArrayList<>();
        for (var el : after) {
            if (!beforeSelectors.contains(el.selector())) {
                String label = !el.text().isEmpty() ? el.text() :
                               !el.placeholder().isEmpty() ? el.placeholder() : el.tag();
                added.add(label);
            }
        }

        // Removed elements
        int removed = 0;
        for (var el : before) {
            if (!afterSelectors.contains(el.selector())) removed++;
        }

        if (added.isEmpty() && removed == 0) return "无变化";
        StringBuilder sb = new StringBuilder();
        if (!added.isEmpty()) {
            sb.append("新增").append(added.size()).append("元素");
            // Show up to 3 new element labels
            String labels = String.join(",", added.subList(0, Math.min(3, added.size())));
            sb.append("(").append(labels).append(")");
        }
        if (removed > 0) {
            if (!sb.isEmpty()) sb.append(",");
            sb.append("消失").append(removed).append("元素");
        }
        return sb.toString();
    }

    /**
     * Format an action for human-readable history.
     */
    private String formatAction(BrowserAction action) {
        return switch (action.type()) {
            case "click" -> "点击 " + action.selector();
            case "fill" -> "填写 " + action.selector() + " = " + action.value();
            case "hover" -> "悬停 " + action.selector();
            case "back" -> "返回上一页";
            default -> action.type() + " " + action.selector();
        };
    }

    private String getStr(JsonObject obj, String key) {
        return obj.has(key) && !obj.get(key).isJsonNull() ? obj.get(key).getAsString() : null;
    }

    // ========== Result Types ==========

    /**
     * Result of an exploration attempt.
     *
     * @param success        whether the target API was triggered
     * @param actionSequence the sequence of actions that triggered the API (empty if failed)
     * @param capturedRequest the captured HTTP request (null if failed)
     * @param actionHistory  human-readable action descriptions
     * @param message        status message
     */
    public record ExploreResult(
            boolean success,
            List<BrowserAction> actionSequence,
            CapturedRequest capturedRequest,
            List<String> actionHistory,
            String message
    ) {
        public static ExploreResult success(List<BrowserAction> actions, CapturedRequest captured, List<String> history) {
            return new ExploreResult(true, actions, captured, history,
                    String.format("成功触发目标 API (%d 步)", actions.size()));
        }

        public static ExploreResult failure(String message) {
            return new ExploreResult(false, List.of(), null, List.of(), message);
        }
    }
}
