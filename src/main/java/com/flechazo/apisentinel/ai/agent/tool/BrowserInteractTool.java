package com.flechazo.apisentinel.ai.agent.tool;

import com.flechazo.apisentinel.browser.BrowserService;
import com.flechazo.apisentinel.browser.BrowserService.ActionResult;
import com.flechazo.apisentinel.browser.BrowserService.BrowserAction;
import com.flechazo.apisentinel.browser.BrowserService.InteractionResult;
import com.flechazo.apisentinel.browser.CapturedRequest;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Agent tool for interacting with a page via browser UI actions.
 *
 * <p>Navigates to a URL and executes an ordered sequence of actions (click, fill,
 * select, wait_for, wait_for_request, etc.), capturing any triggered network requests.
 *
 * <p>Use when: you need to trigger an API through real UI interactions to obtain
 * a request template with valid auth tokens, CSRF tokens, and correct parameter formats.
 */
public class BrowserInteractTool implements AgentTool {

    private final ToolContext ctx;
    private final BrowserService browserService;

    public BrowserInteractTool(ToolContext ctx, BrowserService browserService) {
        this.ctx = ctx;
        this.browserService = browserService;
    }

    @Override
    public String name() { return "browser_interact"; }

    @Override
    public String description() {
        return "Interact with a page via browser UI actions and capture triggered network requests. "
             + "Execute a sequence of: wait_for, click, fill, select, check, type, wait_for_request. "
             + "Returns action results and the captured request (with headers including auth tokens, "
             + "CSRF tokens, cookies) that can be used as a template for send_request. "
             + "Use after browser_find_page + browser_render to determine selectors. "
             + "All browser traffic goes through Burp proxy automatically.";
    }

    @Override
    public JsonObject inputSchema() {
        JsonObject schema = new JsonObject();
        schema.addProperty("type", "object");

        JsonObject props = new JsonObject();
        props.add("url", prop("string", "Page URL to navigate to. Required."));

        // Actions array
        JsonObject actionSchema = new JsonObject();
        actionSchema.addProperty("type", "array");
        actionSchema.addProperty("description",
                "Ordered list of actions to execute on the page.");

        JsonObject actionItem = new JsonObject();
        actionItem.addProperty("type", "object");
        JsonObject actionProps = new JsonObject();
        actionProps.add("type", prop("string",
                "Action type: wait_for, click, fill, select, check, type, wait_for_request, "
                + "hover, scroll, upload, press_key"));
        actionProps.add("selector", prop("string", "CSS or XPath selector (required for most actions)"));
        actionProps.add("value", prop("string", "Value for fill/select/type actions"));
        actionProps.add("timeout_ms", prop("integer", "Timeout in ms (default 5000)"));
        actionProps.add("url_pattern", prop("string",
                "Glob pattern for wait_for_request (e.g. '*/api/v1/orders*')"));
        actionProps.add("delay_ms", prop("integer", "Delay between keystrokes for type action"));
        actionItem.add("properties", actionProps);
        actionItem.add("required", JsonParser.parseString("[\"type\"]"));
        actionSchema.add("items", actionItem);

        props.add("actions", actionSchema);
        props.add("capture_network", prop("boolean",
                "Whether to monitor network requests during interaction. Default: true."));

        schema.add("properties", props);
        schema.add("required", JsonParser.parseString("[\"url\", \"actions\"]"));
        return schema;
    }

    @Override
    public String execute(String argumentsJson) {
        if (browserService == null) {
            return errorJson("Browser service not available. Enable browser in settings.");
        }

        JsonObject args = JsonParser.parseString(argumentsJson).getAsJsonObject();
        String url = getStr(args, "url");
        boolean captureNetwork = !args.has("capture_network")
                || args.get("capture_network").getAsBoolean();

        if (url == null || url.isEmpty()) {
            return errorJson("url is required");
        }

        // Parse actions array
        List<BrowserAction> actions = parseActions(args);
        if (actions.isEmpty()) {
            return errorJson("actions array is required and must not be empty");
        }

        // ── Human approval gate (unless session-auto-approved) ──
        if (!com.flechazo.apisentinel.ui.BrowserInteractConfirmDialog.isSessionAutoApproved()) {
            List<com.flechazo.apisentinel.ui.BrowserInteractConfirmDialog.ActionDesc> descs =
                    new java.util.ArrayList<>();
            for (BrowserAction a : actions) {
                String detail = switch (a.type()) {
                    case "wait_for" -> a.selector();
                    case "click" -> a.selector();
                    case "fill" -> a.selector() + " = \"" + a.value() + "\"";
                    case "select" -> a.selector() + " → " + a.value();
                    case "check" -> a.selector();
                    case "type" -> a.selector() + " = \"" + a.value() + "\"";
                    case "wait_for_request" -> a.urlPattern();
                    default -> a.selector() != null ? a.selector() : a.type();
                };
                descs.add(new com.flechazo.apisentinel.ui.BrowserInteractConfirmDialog.ActionDesc(
                        a.type(), detail));
            }

            java.awt.Frame owner = null;
            try {
                owner = ctx.montoyaApi().userInterface().swingUtils().suiteFrame();
            } catch (Exception ignored) {}

            boolean approved = com.flechazo.apisentinel.ui.BrowserInteractConfirmDialog
                    .confirmBlocking(owner, ctx.montoyaApi(), url, descs,
                            "获取带真实认证 token 的请求模板");
            if (!approved) {
                return errorJson("User rejected browser interaction. "
                        + "Consider using send_request directly with a manually constructed request.");
            }
        }

        try {
            InteractionResult result = browserService.interact(url, actions, captureNetwork);

            JsonObject out = new JsonObject();
            out.addProperty("success", result.success());
            out.addProperty("message", result.message());
            out.addProperty("current_url", result.currentUrl());

            // Action results
            JsonArray resultsArr = new JsonArray();
            for (ActionResult ar : result.actionResults()) {
                JsonObject arObj = new JsonObject();
                arObj.addProperty("step", ar.step());
                arObj.addProperty("type", ar.type());
                arObj.addProperty("success", ar.success());
                arObj.addProperty("message", ar.message());
                resultsArr.add(arObj);
            }
            out.add("action_results", resultsArr);

            // Captured request (the key output for security testing)
            CapturedRequest captured = result.capturedRequest();
            if (captured != null) {
                JsonObject reqObj = new JsonObject();
                reqObj.addProperty("method", captured.method());
                reqObj.addProperty("url", captured.url());
                reqObj.addProperty("body", captured.body());
                reqObj.addProperty("response_status", captured.responseStatus());
                reqObj.addProperty("response_body_snippet", captured.responseBodySnippet());

                // Headers — critical for security testing (auth, CSRF, cookies)
                JsonObject headersObj = new JsonObject();
                if (captured.headers() != null) {
                    for (Map.Entry<String, String> h : captured.headers().entrySet()) {
                        headersObj.addProperty(h.getKey(), h.getValue());
                    }
                }
                reqObj.add("headers", headersObj);

                out.add("captured_request", reqObj);
                out.addProperty("note",
                        "Use the captured_request as a template for send_request. "
                        + "The headers include real auth tokens and CSRF tokens from the browser session.");
            } else {
                out.addProperty("captured_request", (String) null);
                out.addProperty("note",
                        "No request was captured. Add a wait_for_request action to capture "
                        + "the API call triggered by the UI interaction.");
            }

            return out.toString();

        } catch (Exception e) {
            return errorJson("browser_interact failed: " + e.getMessage());
        }
    }

    /**
     * Parse the actions array from the JSON arguments.
     */
    private List<BrowserAction> parseActions(JsonObject args) {
        List<BrowserAction> actions = new ArrayList<>();

        if (!args.has("actions") || !args.get("actions").isJsonArray()) {
            return actions;
        }

        JsonArray actionsArr = args.getAsJsonArray("actions");
        for (JsonElement elem : actionsArr) {
            if (!elem.isJsonObject()) continue;
            JsonObject aObj = elem.getAsJsonObject();

            String type = getStr(aObj, "type");
            if (type == null) continue;

            String selector = getStr(aObj, "selector");
            String value = getStr(aObj, "value");
            int timeoutMs = aObj.has("timeout_ms") ? aObj.get("timeout_ms").getAsInt() : 0;
            String urlPattern = getStr(aObj, "url_pattern");
            int delayMs = aObj.has("delay_ms") ? aObj.get("delay_ms").getAsInt() : 0;

            actions.add(new BrowserAction(type, selector, value, timeoutMs, urlPattern, delayMs));
        }

        return actions;
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
