package com.flechazo.apisentinel.ai.agent.tool;

import com.flechazo.apisentinel.browser.BrowserService;
import com.flechazo.apisentinel.browser.BrowserService.PageLocationResult;
import com.flechazo.apisentinel.browser.PageLocator.CandidatePage;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

/**
 * Agent tool for reverse-locating which frontend page invokes a given API.
 *
 * <p>Given an API method + path, finds candidate frontend pages using a
 * three-level strategy: JS Bundle search → Crawl mapping → RESTful path inference.
 *
 * <p>Use when: you need to find the frontend page that triggers a specific API
 * call, so you can use browser_interact to trigger it with real auth tokens.
 */
public class BrowserFindPageTool implements AgentTool {

    private final ToolContext ctx;
    private final BrowserService browserService;

    public BrowserFindPageTool(ToolContext ctx, BrowserService browserService) {
        this.ctx = ctx;
        this.browserService = browserService;
    }

    @Override
    public String name() { return "browser_find_page"; }

    @Override
    public String description() {
        return "Find which frontend page invokes a given API endpoint. "
             + "Uses three-level strategy: JS Bundle search (high confidence) → "
             + "Crawl mapping (medium) → RESTful path inference (low, always available). "
             + "Use when: you have an API but no captured traffic, and need to trigger it "
             + "via browser UI to get real auth tokens/CSRF/parameters. "
             + "Follow up with browser_render to inspect the page, then browser_interact to operate it. "
             + "frontend_base_url is optional — if omitted, the target API's domain is used automatically.";
    }

    @Override
    public JsonObject inputSchema() {
        JsonObject schema = new JsonObject();
        schema.addProperty("type", "object");
        JsonObject props = new JsonObject();
        props.add("api_method", prop("string",
                "HTTP method of the target API (e.g. 'POST'). Required."));
        props.add("api_path", prop("string",
                "API path (e.g. '/api/v1/orders'). Required."));
        props.add("frontend_base_url", prop("string",
                "Frontend base URL (e.g. 'http://localhost:3000'). "
                + "Optional — auto-derived from the target API's domain if omitted."));
        schema.add("properties", props);
        schema.add("required", JsonParser.parseString("[\"api_method\", \"api_path\"]"));
        return schema;
    }

    @Override
    public String execute(String argumentsJson) {
        if (browserService == null) {
            return errorJson("Browser service not available. Enable browser in settings.");
        }

        JsonObject args = JsonParser.parseString(argumentsJson).getAsJsonObject();
        String apiMethod = getStr(args, "api_method");
        String apiPath = getStr(args, "api_path");
        String frontendBaseUrl = getStr(args, "frontend_base_url");

        if (apiMethod == null || apiMethod.isEmpty()) {
            return errorJson("api_method is required");
        }
        if (apiPath == null || apiPath.isEmpty()) {
            return errorJson("api_path is required");
        }

        // Auto-derive frontend URL from the API entry's domain when not provided
        if (frontendBaseUrl == null || frontendBaseUrl.isEmpty()) {
            String domain = ctx.entry() != null ? ctx.entry().getDomain() : null;
            if (domain != null && !domain.isEmpty()) {
                // Ensure it has a scheme
                if (!domain.startsWith("http://") && !domain.startsWith("https://")) {
                    frontendBaseUrl = "http://" + domain;
                } else {
                    frontendBaseUrl = domain;
                }
            }
        }

        try {
            PageLocationResult result = browserService.findPageForApi(apiMethod, apiPath, frontendBaseUrl);

            JsonObject out = new JsonObject();
            out.addProperty("found", result.found());
            out.addProperty("strategy", result.strategy());
            out.addProperty("message", result.message());

            JsonArray candidatesArr = new JsonArray();
            for (CandidatePage candidate : result.candidates()) {
                JsonObject cObj = new JsonObject();
                cObj.addProperty("url", candidate.url());
                cObj.addProperty("confidence", candidate.confidence());
                cObj.addProperty("reason", candidate.reason());
                candidatesArr.add(cObj);
            }
            out.add("candidate_pages", candidatesArr);
            out.addProperty("candidate_count", result.candidates().size());

            if (result.found()) {
                out.addProperty("next_step",
                        "Use browser_render on the top candidate URL to inspect the page DOM/forms, "
                        + "then browser_interact to fill forms and trigger the API.");
            } else {
                out.addProperty("next_step",
                        "No candidate pages found via JS bundle or crawl mapping. "
                        + "Use browser_discover first to find frontend routes, "
                        + "or use browser_render directly on the frontend URL to inspect the DOM.");
            }

            return out.toString();

        } catch (Exception e) {
            return errorJson("browser_find_page failed: " + e.getMessage());
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
