package com.flechazo.apisentinel.ai.agent.tool;

import com.flechazo.apisentinel.browser.BrowserService;
import com.flechazo.apisentinel.browser.BrowserService.DomXssResult;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

/**
 * Agent tool for detecting DOM-based XSS vulnerabilities.
 *
 * <p>Analyzes JS code for dangerous sinks (innerHTML, document.write, eval, etc.)
 * and tests if payloads in URL hash/parameters get executed.
 */
public class BrowserDomXssTool implements AgentTool {

    private final ToolContext ctx;
    private final BrowserService browserService;

    public BrowserDomXssTool(ToolContext ctx, BrowserService browserService) {
        this.ctx = ctx;
        this.browserService = browserService;
    }

    @Override
    public String name() { return "browser_dom_xss"; }

    @Override
    public String description() {
        return "Detect DOM-based XSS vulnerabilities using a real browser. "
             + "Analyzes JS for dangerous sinks (innerHTML, document.write, eval) and tests "
             + "if XSS payloads in URL hash get executed. "
             + "Use when: grep_repo found innerHTML/document.write, or you suspect client-side XSS. "
             + "Returns: whether XSS was detected, sinks found, CSP status.";
    }

    @Override
    public JsonObject inputSchema() {
        JsonObject schema = new JsonObject();
        schema.addProperty("type", "object");
        JsonObject props = new JsonObject();
        props.add("url", prop("string", "URL to test for DOM XSS (required)"));
        props.add("test_hash", prop("boolean", "Test URL hash injection. Default: true"));
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

        if (url == null || url.isEmpty()) {
            return errorJson("url is required");
        }

        try {
            DomXssResult result = browserService.detectDomXss(url);

            JsonObject out = new JsonObject();
            out.addProperty("success", "OK".equals(result.message()));
            out.addProperty("xss_detected", result.xssDetected());
            out.addProperty("csp_blocked", result.cspBlocked());
            out.addProperty("status", result.status());

            // Sinks found
            JsonArray sinksArr = new JsonArray();
            result.sinksFound().forEach(sinksArr::add);
            out.add("sinks_found", sinksArr);
            out.addProperty("sink_count", result.sinksFound().size());

            // Verdict
            if (result.xssDetected()) {
                out.addProperty("verdict", "VULNERABLE");
                out.addProperty("note", "DOM XSS confirmed: payload was executed in the browser. "
                        + "This is a real vulnerability that HTTP-layer analysis cannot detect.");
            } else if (result.cspBlocked()) {
                out.addProperty("verdict", "MITIGATED");
                out.addProperty("note", "XSS sinks found but payload was blocked by CSP. "
                        + "Check if CSP can be bypassed (nonce reuse, JSONP endpoints).");
            } else if (!result.sinksFound().isEmpty()) {
                out.addProperty("verdict", "POTENTIAL");
                out.addProperty("note", "XSS sinks found but payload did not trigger. "
                        + "The sinks may require specific input patterns to reach.");
            } else {
                out.addProperty("verdict", "SAFE");
                out.addProperty("note", "No dangerous JS sinks found on this page.");
            }

            return out.toString();

        } catch (Exception e) {
            return errorJson("DOM XSS detection failed: " + e.getMessage());
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
