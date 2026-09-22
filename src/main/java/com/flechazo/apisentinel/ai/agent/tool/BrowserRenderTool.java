package com.flechazo.apisentinel.ai.agent.tool;

import com.flechazo.apisentinel.browser.BrowserService;
import com.flechazo.apisentinel.browser.BrowserService.RenderResult;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

/**
 * Agent tool for rendering a page in a real browser and extracting DOM/runtime info.
 *
 * <p>Useful for:
 * <ul>
 *   <li>Getting JS-rendered content that HTTP layer can't see</li>
 *   <li>Checking CSP violations</li>
 *   <li>Extracting frontend routes</li>
 *   <li>Viewing console logs for debugging</li>
 * </ul>
 */
public class BrowserRenderTool implements AgentTool {

    private static final int MAX_DOM_LENGTH = 10000;

    private final ToolContext ctx;
    private final BrowserService browserService;

    public BrowserRenderTool(ToolContext ctx, BrowserService browserService) {
        this.ctx = ctx;
        this.browserService = browserService;
    }

    @Override
    public String name() { return "browser_render"; }

    @Override
    public String description() {
        return "Render a page in a real browser and extract DOM, console logs, CSP violations, "
             + "and frontend routes. Use when: you need to see JS-rendered content, verify CSP, "
             + "or check what the browser actually displays. "
             + "All browser traffic goes through Burp proxy automatically.";
    }

    @Override
    public JsonObject inputSchema() {
        JsonObject schema = new JsonObject();
        schema.addProperty("type", "object");
        JsonObject props = new JsonObject();
        props.add("url", prop("string", "URL to render (required)"));
        props.add("include_dom", prop("boolean", "Include rendered DOM in output. Default: true"));
        props.add("truncate_dom", prop("boolean", "Truncate DOM to 10000 chars. Default: true"));
        schema.add("properties", props);
        schema.add("required", JsonParser.parseString("[\"url\"]"));
        return schema;
    }

    @Override
    public String execute(String argumentsJson) {
        if (browserService == null) {
            return errorJson("Browser service not available. Enable browser in settings.");
        }

        JsonObject args = JsonParser.parseString(argumentsJson).getAsJsonObject();
        String url = getStr(args, "url");
        boolean includeDom = !args.has("include_dom") || args.get("include_dom").getAsBoolean();
        boolean truncateDom = !args.has("truncate_dom") || args.get("truncate_dom").getAsBoolean();

        if (url == null || url.isEmpty()) {
            return errorJson("url is required");
        }

        try {
            RenderResult result = browserService.renderPage(url);

            JsonObject out = new JsonObject();
            out.addProperty("success", "OK".equals(result.status()));
            out.addProperty("status", result.status());
            out.addProperty("title", result.title());

            if (includeDom) {
                String dom = result.dom();
                if (truncateDom && dom.length() > MAX_DOM_LENGTH) {
                    dom = dom.substring(0, MAX_DOM_LENGTH) + "\n<!-- TRUNCATED -->";
                }
                out.addProperty("dom", dom);
                out.addProperty("dom_length", result.dom().length());
            }

            // Console logs (limit to 50)
            JsonArray logsArr = new JsonArray();
            result.consoleLogs().stream().limit(50).forEach(logsArr::add);
            out.add("console_logs", logsArr);
            out.addProperty("console_log_count", result.consoleLogs().size());

            // CSP violations
            JsonArray cspArr = new JsonArray();
            result.cspViolations().forEach(cspArr::add);
            out.add("csp_violations", cspArr);

            // Frontend routes
            JsonArray routesArr = new JsonArray();
            result.frontendRoutes().forEach(routesArr::add);
            out.add("frontend_routes", routesArr);

            return out.toString();

        } catch (Exception e) {
            return errorJson("Browser render failed: " + e.getMessage());
        }
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
