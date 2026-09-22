package com.flechazo.apisentinel.ai.agent.tool;

import com.flechazo.apisentinel.browser.BrowserService;
import com.flechazo.apisentinel.browser.BrowserService.DiscoveryResult;
import com.flechazo.apisentinel.browser.DiscoveredApi;
import com.flechazo.apisentinel.browser.JsAnalyzer.SecretFinding;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

/**
 * Agent tool for discovering APIs from the frontend application.
 *
 * <p>Opens a browser, navigates through the frontend, captures network requests,
 * analyzes JS bundles, and extracts frontend routes to discover undocumented APIs.
 */
public class BrowserDiscoverTool implements AgentTool {

    private final ToolContext ctx;
    private final BrowserService browserService;

    public BrowserDiscoverTool(ToolContext ctx, BrowserService browserService) {
        this.ctx = ctx;
        this.browserService = browserService;
    }

    @Override
    public String name() { return "browser_discover"; }

    @Override
    public String description() {
        return "Discover APIs from the frontend application using a real browser. "
             + "Opens the target URL, monitors network requests (XHR/Fetch), analyzes JS bundles "
             + "for hardcoded endpoints and secrets, and extracts frontend routes (Vue Router, React Router). "
             + "Use when: target is a SPA, API table may be incomplete, or you suspect undocumented APIs. "
             + "All browser traffic goes through Burp proxy automatically. "
             + "Returns: discovered APIs, JS secrets, internal URLs, XSS sinks.";
    }

    @Override
    public JsonObject inputSchema() {
        JsonObject schema = new JsonObject();
        schema.addProperty("type", "object");
        JsonObject props = new JsonObject();
        props.add("url", prop("string", "Starting URL to explore (required)"));
        props.add("explore_depth", prop("integer",
                "Exploration depth: 1=shallow (current page only), 2=medium (follow some links), "
                + "3=deep (follow more links). Default: 2"));
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
        int depth = args.has("explore_depth") ? args.get("explore_depth").getAsInt() : 2;

        if (url == null || url.isEmpty()) {
            return errorJson("url is required");
        }

        try {
            DiscoveryResult result = browserService.discoverApis(url, depth);

            JsonObject out = new JsonObject();
            out.addProperty("success", true);
            out.addProperty("summary", result.summary());

            // APIs
            JsonArray apisArr = new JsonArray();
            for (DiscoveredApi api : result.apis()) {
                JsonObject apiObj = new JsonObject();
                apiObj.addProperty("method", api.method());
                apiObj.addProperty("path", api.path());
                apiObj.addProperty("source", api.source());
                apiObj.addProperty("discovered_in", api.discoveredIn());
                apisArr.add(apiObj);
            }
            out.add("discovered_apis", apisArr);
            out.addProperty("api_count", result.apis().size());

            // Secrets
            JsonArray secretsArr = new JsonArray();
            for (SecretFinding secret : result.secrets()) {
                JsonObject secretObj = new JsonObject();
                secretObj.addProperty("type", secret.type());
                secretObj.addProperty("value", secret.value());
                secretObj.addProperty("context", secret.context());
                secretsArr.add(secretObj);
            }
            out.add("js_secrets", secretsArr);

            // Internal URLs
            JsonArray internalArr = new JsonArray();
            result.internalUrls().forEach(internalArr::add);
            out.add("internal_urls", internalArr);

            // XSS sinks
            JsonArray sinksArr = new JsonArray();
            result.xssSinks().forEach(sinksArr::add);
            out.add("xss_sinks", sinksArr);

            out.addProperty("note", "Use register_discovered_apis to add new APIs to the analysis queue. "
                    + "Check js_secrets for leaked API keys and xss_sinks for potential DOM XSS.");

            return out.toString();

        } catch (Exception e) {
            return errorJson("Browser discovery failed: " + e.getMessage());
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
