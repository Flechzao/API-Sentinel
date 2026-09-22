package com.flechazo.apisentinel.ai.agent.tool;

import com.flechazo.apisentinel.ai.provider.LlmProvider;
import com.flechazo.apisentinel.browser.BrowserManager;
import com.flechazo.apisentinel.browser.BrowserService;
import com.flechazo.apisentinel.browser.BrowserService.BrowserAction;
import com.flechazo.apisentinel.browser.CapturedRequest;
import com.flechazo.apisentinel.browser.ExplorationEngine;
import com.flechazo.apisentinel.browser.ExplorationEngine.ExploreResult;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import java.util.ArrayList;
import java.util.List;

/**
 * Agent tool for intelligent browser exploration to trigger target APIs.
 *
 * <p>Automatically navigates through a web application's UI (clicking menus,
 * tabs, buttons, filling forms) to find and trigger a specific API endpoint.
 * Uses LLM to make navigation decisions based on the current page's elements.
 *
 * <p>Use when: you know the API endpoint but not which page/action triggers it,
 * or the API requires multi-step navigation (deep menus, tabs, wizards).
 *
 * <p>Features:
 * <ul>
 *   <li>LLM-powered navigation decisions</li>
 *   <li>Loop detection and backtracking</li>
 *   <li>Cached exploration paths for reuse</li>
 *   <li>Optional hints to guide exploration</li>
 * </ul>
 */
public class BrowserExploreTool implements AgentTool {

    private final ToolContext ctx;
    private final BrowserService browserService;
    private final LlmProvider llmProvider;

    public BrowserExploreTool(ToolContext ctx, BrowserService browserService, LlmProvider llmProvider) {
        this.ctx = ctx;
        this.browserService = browserService;
        this.llmProvider = llmProvider;
    }

    @Override
    public String name() { return "browser_explore"; }

    @Override
    public String description() {
        return "Intelligently explore a web application to trigger a target API. "
             + "Automatically clicks through menus, tabs, and forms to find the path "
             + "that invokes the specified API endpoint. Uses LLM to make navigation decisions. "
             + "Use when: you know the API but not which page/action triggers it, "
             + "or the API requires multi-step navigation (deep menus, tabs, wizards). "
             + "Returns: the action sequence (cached for future replay) and captured request. "
             + "All browser traffic goes through Burp proxy automatically.";
    }

    @Override
    public JsonObject inputSchema() {
        JsonObject schema = new JsonObject();
        schema.addProperty("type", "object");

        JsonObject props = new JsonObject();
        props.add("target_api", prop("string",
                "Target API to trigger (required). Format: 'METHOD /path' or just '/path'. "
                + "Example: 'POST /api/v1/roles' or '/api/v1/users'."));
        props.add("start_url", prop("string",
                "Starting URL for exploration (required). Usually the app homepage "
                + "or a known entry point. Example: 'http://localhost:3000'."));
        props.add("max_depth", prop("integer",
                "Maximum exploration depth (default: 10). How many clicks/actions to try "
                + "before giving up. Increase for deeply nested menus."));
        props.add("hints", prop("array",
                "Optional hints to guide exploration. Array of strings describing where "
                + "the feature might be. Example: ['在权限管理菜单下', '需要管理员权限']."));

        schema.add("properties", props);
        schema.add("required", JsonParser.parseString("[\"target_api\", \"start_url\"]"));
        return schema;
    }

    @Override
    public String execute(String argumentsJson) {
        if (browserService == null) {
            return errorJson("Browser service not available. Enable browser in settings.");
        }
        if (llmProvider == null) {
            return errorJson("LLM provider not available. Configure AI settings.");
        }

        JsonObject args = JsonParser.parseString(argumentsJson).getAsJsonObject();

        String targetApi = getStr(args, "target_api");
        String startUrl = getStr(args, "start_url");
        int maxDepth = args.has("max_depth") ? args.get("max_depth").getAsInt() : 10;
        List<String> hints = new ArrayList<>();

        if (args.has("hints") && args.get("hints").isJsonArray()) {
            for (var el : args.getAsJsonArray("hints")) {
                if (el.isJsonPrimitive()) {
                    hints.add(el.getAsString());
                }
            }
        }

        if (targetApi == null || targetApi.isEmpty()) {
            return errorJson("target_api is required");
        }
        if (startUrl == null || startUrl.isEmpty()) {
            return errorJson("start_url is required");
        }

        // Create exploration engine
        BrowserManager browserManager = browserService.getBrowserManager();
        ExplorationEngine engine = new ExplorationEngine(ctx.logger(), browserManager, llmProvider);
        // Use fast model for vision decisions if configured
        if (ctx.fastModel() != null && !ctx.fastModel().isBlank()) {
            engine.setVisionModelOverride(ctx.fastModel());
        }

        // Run exploration
        ExploreResult result = engine.explore(startUrl, targetApi, maxDepth, hints);

        // Build response
        JsonObject out = new JsonObject();
        out.addProperty("success", result.success());
        out.addProperty("message", result.message());

        if (result.success()) {
            // Action sequence
            JsonArray actionsArr = new JsonArray();
            for (BrowserAction action : result.actionSequence()) {
                JsonObject actionObj = new JsonObject();
                actionObj.addProperty("type", action.type());
                if (action.selector() != null) actionObj.addProperty("selector", action.selector());
                if (action.value() != null) actionObj.addProperty("value", action.value());
                actionsArr.add(actionObj);
            }
            out.add("action_sequence", actionsArr);
            out.addProperty("step_count", result.actionSequence().size());

            // Action history (human-readable)
            JsonArray historyArr = new JsonArray();
            for (String h : result.actionHistory()) {
                historyArr.add(h);
            }
            out.add("action_history", historyArr);

            // Captured request
            if (result.capturedRequest() != null) {
                CapturedRequest req = result.capturedRequest();
                JsonObject reqObj = new JsonObject();
                reqObj.addProperty("method", req.method());
                reqObj.addProperty("url", req.url());
                reqObj.addProperty("request_body", req.body());
                reqObj.addProperty("response_status", req.responseStatus());
                reqObj.addProperty("response_snippet", req.responseBodySnippet());
                out.add("captured_request", reqObj);
            }

            out.addProperty("note", "Action sequence has been cached. Future explorations for this API "
                    + "will replay the cached path automatically. You can use the captured request "
                    + "as a template for send_request with different parameters.");
        } else {
            out.addProperty("troubleshooting",
                    "Common causes: 1) Target API path is wrong or doesn't exist, "
                    + "2) Feature requires specific permissions (try logging in as admin), "
                    + "3) Max depth too low for deeply nested menus, "
                    + "4) Page structure changed. "
                    + "Try: providing hints, increasing max_depth, or using browser_interact manually.");
        }

        return out.toString();
    }

    private JsonObject prop(String type, String desc) {
        JsonObject p = new JsonObject();
        p.addProperty("type", type);
        p.addProperty("description", desc);
        return p;
    }

    private String getStr(JsonObject obj, String key) {
        return obj.has(key) && !obj.get(key).isJsonNull() ? obj.get(key).getAsString() : null;
    }

    private String errorJson(String msg) {
        JsonObject out = new JsonObject();
        out.addProperty("success", false);
        out.addProperty("error", msg);
        return out.toString();
    }
}
