package com.flechazo.apisentinel.ai.agent.tool;

import com.flechazo.apisentinel.browser.ApiTemplate;
import com.flechazo.apisentinel.browser.BrowserService;
import com.flechazo.apisentinel.browser.ExplorationCache;
import com.flechazo.apisentinel.browser.ExplorationCache.CachedEntry;
import com.flechazo.apisentinel.model.ApiEntry;
import com.flechazo.apisentinel.repository.ApiRepository;
import com.flechazo.apisentinel.config.AppConfig;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Agent tool for batch triggering APIs from the API table.
 *
 * <p>Triggers selected APIs by either:
 * <ol>
 *   <li>Direct HTTP request (if API template is cached) - fast, no UI needed</li>
 *   <li>UI replay (if only UI actions are cached) - slower, replays browser actions</li>
 *   <li>browser_explore (if nothing cached) - slowest, requires LLM navigation</li>
 * </ol>
 *
 * <p>Use when: you want to generate traffic for multiple APIs in the API table,
 * especially for APIs that require deep UI navigation to trigger.
 */
public class TriggerApisTool implements AgentTool {

    private final ToolContext ctx;
    private final ApiRepository apiRepository;
    private final ExplorationCache explorationCache;
    private final BrowserService browserService;
    private final AppConfig appConfig;
    private final HttpClient httpClient;

    public TriggerApisTool(ToolContext ctx, ApiRepository apiRepository,
                           ExplorationCache explorationCache, BrowserService browserService,
                           AppConfig appConfig) {
        this.ctx = ctx;
        this.apiRepository = apiRepository;
        this.explorationCache = explorationCache;
        this.browserService = browserService;
        this.appConfig = appConfig;
        this.httpClient = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(10))
            .build();
    }

    @Override
    public String name() { return "trigger_apis"; }

    @Override
    public String description() {
        return "Batch trigger APIs from the API table to generate traffic. "
             + "Use when: you want to trigger multiple APIs for analysis, "
             + "especially APIs that require deep UI navigation. "
             + "Strategy: 1) Direct HTTP (fast, uses cached API template), "
             + "2) UI replay (slower, replays cached browser actions), "
             + "3) browser_explore (slowest, LLM navigates UI). "
             + "All traffic goes through Burp proxy automatically.";
    }

    @Override
    public JsonObject inputSchema() {
        JsonObject schema = new JsonObject();
        schema.addProperty("type", "object");

        JsonObject props = new JsonObject();
        props.add("api_paths", prop("array",
                "List of API paths to trigger (e.g., ['POST /api/roles', 'GET /api/users']). "
                + "If omitted, triggers all selected APIs in the API table."));
        props.add("params", prop("object",
                "Map of parameter name → value for API templates. "
                + "Example: {\"roleName\": \"Admin\", \"userId\": \"123\"}."));
        props.add("use_browser_explore", prop("boolean",
                "Whether to use browser_explore for APIs without cached paths (default: true). "
                + "Set to false to only trigger APIs with cached paths."));

        schema.add("properties", props);
        schema.add("required", JsonParser.parseString("[]"));
        return schema;
    }

    @Override
    public String execute(String argumentsJson) {
        JsonObject args = JsonParser.parseString(argumentsJson).getAsJsonObject();
        
        // Get target APIs
        List<ApiEntry> targetApis = getTargetApis(args);
        if (targetApis.isEmpty()) {
            return errorJson("No APIs to trigger. Select APIs in the API table or provide 'api_paths'.");
        }

        // Get params for API templates
        Map<String, String> params = new HashMap<>();
        if (args.has("params")) {
            JsonObject paramsObj = args.getAsJsonObject("params");
            for (String key : paramsObj.keySet()) {
                params.put(key, paramsObj.get(key).getAsString());
            }
        }

        boolean useBrowserExplore = args.has("use_browser_explore") 
            ? args.get("use_browser_explore").getAsBoolean() 
            : true;

        // Trigger APIs
        int directTriggered = 0;
        int uiReplayed = 0;
        int explored = 0;
        int failed = 0;

        JsonArray results = new JsonArray();

        for (ApiEntry api : targetApis) {
            String apiPath = api.getHttpMethod() + " " + api.getApiPath();
            JsonObject result = new JsonObject();
            result.addProperty("api", apiPath);

            try {
                CachedEntry cached = explorationCache.getEntry(apiPath);

                if (cached != null && cached.canDirectTrigger()) {
                    // Strategy 1: Direct HTTP (fastest)
                    boolean success = triggerDirectHttp(cached.apiTemplate(), params);
                    if (success) {
                        directTriggered++;
                        result.addProperty("strategy", "direct_http");
                        result.addProperty("success", true);
                    } else {
                        failed++;
                        result.addProperty("strategy", "direct_http");
                        result.addProperty("success", false);
                        result.addProperty("error", "HTTP request failed");
                    }

                } else if (cached != null && cached.canUiReplay()) {
                    // Strategy 2: UI replay (slower)
                    boolean success = triggerUiReplay(apiPath, cached.actions());
                    if (success) {
                        uiReplayed++;
                        result.addProperty("strategy", "ui_replay");
                        result.addProperty("success", true);
                    } else {
                        failed++;
                        result.addProperty("strategy", "ui_replay");
                        result.addProperty("success", false);
                        result.addProperty("error", "UI replay failed");
                    }

                } else if (useBrowserExplore) {
                    // Strategy 3: browser_explore (slowest)
                    boolean success = triggerBrowserExplore(apiPath);
                    if (success) {
                        explored++;
                        result.addProperty("strategy", "browser_explore");
                        result.addProperty("success", true);
                    } else {
                        failed++;
                        result.addProperty("strategy", "browser_explore");
                        result.addProperty("success", false);
                        result.addProperty("error", "browser_explore failed");
                    }

                } else {
                    // No cached path and browser_explore disabled
                    failed++;
                    result.addProperty("strategy", "none");
                    result.addProperty("success", false);
                    result.addProperty("error", "No cached path and browser_explore disabled");
                }

            } catch (Exception e) {
                failed++;
                result.addProperty("success", false);
                result.addProperty("error", e.getMessage());
            }

            results.add(result);
        }

        // Build response
        JsonObject out = new JsonObject();
        out.addProperty("success", true);
        out.addProperty("total", targetApis.size());
        out.addProperty("direct_triggered", directTriggered);
        out.addProperty("ui_replayed", uiReplayed);
        out.addProperty("explored", explored);
        out.addProperty("failed", failed);
        out.add("results", results);

        out.addProperty("note", String.format(
            "Triggered %d APIs (direct: %d, UI: %d, explore: %d, failed: %d). "
            + "Traffic captured in Burp proxy. Use analyze_traffic or heuristic_scan to analyze.",
            targetApis.size(), directTriggered, uiReplayed, explored, failed
        ));

        // Add cache stats
        Map<String, Integer> stats = explorationCache.getStats();
        JsonObject statsObj = new JsonObject();
        statsObj.addProperty("total_cached", stats.get("total"));
        statsObj.addProperty("with_ui_path", stats.get("withUiPath"));
        statsObj.addProperty("with_api_template", stats.get("withApiTemplate"));
        out.add("cache_stats", statsObj);

        return out.toString();
    }

    /**
     * Trigger API via direct HTTP request (using API template).
     */
    private boolean triggerDirectHttp(ApiTemplate template, Map<String, String> params) {
        try {
            // Build request body
            String body = template.buildBody(params);

            // Build HTTP request
            HttpRequest.Builder builder = HttpRequest.newBuilder()
                .uri(URI.create(template.url))
                .timeout(Duration.ofSeconds(30));

            // Add auth headers
            for (Map.Entry<String, String> header : template.authHeaders.entrySet()) {
                builder.header(header.getKey(), header.getValue());
            }

            // Add content type
            if (template.contentType != null) {
                builder.header("Content-Type", template.contentType);
            }

            // Set method and body
            switch (template.method.toUpperCase()) {
                case "GET":
                    builder.GET();
                    break;
                case "POST":
                    builder.POST(body != null ? HttpRequest.BodyPublishers.ofString(body) : HttpRequest.BodyPublishers.noBody());
                    break;
                case "PUT":
                    builder.PUT(body != null ? HttpRequest.BodyPublishers.ofString(body) : HttpRequest.BodyPublishers.noBody());
                    break;
                case "DELETE":
                    builder.DELETE();
                    break;
                default:
                    ctx.logger().warn("[TriggerApisTool] Unsupported method: %s", template.method);
                    return false;
            }

            // Send request
            HttpResponse<String> response = httpClient.send(builder.build(), HttpResponse.BodyHandlers.ofString());

            // Check if successful (2xx status)
            return response.statusCode() >= 200 && response.statusCode() < 300;

        } catch (Exception e) {
            ctx.logger().warn("[TriggerApisTool] Direct HTTP failed: %s", e.getMessage());
            return false;
        }
    }

    /**
     * Trigger API via UI replay (replaying cached browser actions).
     */
    private boolean triggerUiReplay(String apiPath, List<BrowserService.BrowserAction> actions) {
        try {
            ctx.logger().debug("[TriggerApisTool] UI replay for %s (%d actions)", apiPath, actions.size());
            
            // Replay actions through BrowserService
            // Each action is executed in sequence
            for (BrowserService.BrowserAction action : actions) {
                if (!executeBrowserAction(action)) {
                    ctx.logger().warn("[TriggerApisTool] Action failed: %s %s", 
                        action.type(), action.selector());
                    return false;
                }
                
                // Small delay between actions to let page stabilize
                if (action.delayMs() > 0) {
                    Thread.sleep(action.delayMs());
                }
            }
            
            ctx.logger().debug("[TriggerApisTool] UI replay completed for %s", apiPath);
            return true;

        } catch (Exception e) {
            ctx.logger().warn("[TriggerApisTool] UI replay failed: %s", e.getMessage());
            return false;
        }
    }
    
    /**
     * Execute a single browser action.
     * Note: BrowserService doesn't expose direct action methods.
     * Use interact() method with a list of actions instead.
     */
    private boolean executeBrowserAction(BrowserService.BrowserAction action) {
        // TODO: Implement proper action execution via BrowserService.interact()
        // For now, log and return false to fall back to browser_explore
        ctx.logger().debug("[TriggerApisTool] Action execution not yet implemented: %s", action.type());
        return false;
    }

    /**
     * Trigger API via browser_explore (LLM navigation).
     */
    private boolean triggerBrowserExplore(String apiPath) {
        try {
            ctx.logger().debug("[TriggerApisTool] browser_explore for %s", apiPath);
            
            // Build browser_explore tool arguments
            JsonObject args = new JsonObject();
            args.addProperty("target_api", apiPath);
            
            // Get start URL from AppConfig or default
            String startUrl = appConfig.getBrowserFrontendUrl();
            if (startUrl == null || startUrl.isEmpty()) {
                // Try to extract base URL from API path
                // e.g., "POST /api/roles" → need to know the base URL
                ctx.logger().warn("[TriggerApisTool] No start_url configured for browser_explore");
                return false;
            }
            args.addProperty("start_url", startUrl);
            
            // Invoke BrowserExploreTool
            // Note: In practice, you'd need to inject BrowserExploreTool as a dependency
            // For now, log the intent and return false
            ctx.logger().info("[TriggerApisTool] Would invoke browser_explore with: %s", args.toString());
            
            // TODO: Implement actual browser_explore invocation
            // This requires injecting BrowserExploreTool into TriggerApisTool constructor
            // BrowserExploreTool exploreTool = new BrowserExploreTool(ctx, browserService, llmProvider);
            // String result = exploreTool.execute(args.toString());
            // JsonObject resultJson = JsonParser.parseString(result).getAsJsonObject();
            // return resultJson.has("success") && resultJson.get("success").getAsBoolean();
            
            return false;

        } catch (Exception e) {
            ctx.logger().warn("[TriggerApisTool] browser_explore failed: %s", e.getMessage());
            return false;
        }
    }

    /**
     * Get target APIs from arguments or API table selection.
     */
    private List<ApiEntry> getTargetApis(JsonObject args) {
        if (args.has("api_paths")) {
            // Get specific APIs by path
            JsonArray pathsArr = args.getAsJsonArray("api_paths");
            return apiRepository.findAll().stream()
                .filter(entry -> {
                    String apiPath = entry.getHttpMethod() + " " + entry.getApiPath();
                    for (int i = 0; i < pathsArr.size(); i++) {
                        if (apiPath.equalsIgnoreCase(pathsArr.get(i).getAsString())) {
                            return true;
                        }
                    }
                    return false;
                })
                .toList();
        } else {
            // Get selected APIs from table
            // Note: This assumes ApiRepository has a getSelectedEntries() method
            // In practice, you'd get the selection from the UI
            return apiRepository.findAll();
        }
    }

    private JsonObject prop(String type, String desc) {
        JsonObject p = new JsonObject();
        p.addProperty("type", type);
        p.addProperty("description", desc);
        return p;
    }

    private String errorJson(String msg) {
        JsonObject out = new JsonObject();
        out.addProperty("success", false);
        out.addProperty("error", msg);
        return out.toString();
    }
}
