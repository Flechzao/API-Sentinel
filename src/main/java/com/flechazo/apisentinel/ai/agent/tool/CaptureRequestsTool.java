package com.flechazo.apisentinel.ai.agent.tool;

import com.flechazo.apisentinel.browser.AgentBrowserCli;
import com.flechazo.apisentinel.browser.ApiExtractionService;
import com.flechazo.apisentinel.browser.BrowserService;
import com.flechazo.apisentinel.browser.CapturedRequest;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import java.io.File;
import java.util.List;

/**
 * Agent tool for capturing request templates from browser network traffic.
 *
 * <p>Uses agent-browser to capture HTTP requests from the current browser session.
 * Captured requests can be filtered by type (XHR/Fetch), status code, or HTTP method.
 * Templates are saved to disk for later reuse.
 *
 * <p>Use when: you need to understand the structure of API requests triggered by UI interactions,
 * or you want to save request templates for batch triggering.
 */
public class CaptureRequestsTool implements AgentTool {

    private final ToolContext ctx;
    private final BrowserService browserService;
    private final ApiExtractionService extractionService;

    public CaptureRequestsTool(ToolContext ctx, BrowserService browserService) {
        this.ctx = ctx;
        this.browserService = browserService;
        this.extractionService = new ApiExtractionService(browserService);
    }

    @Override
    public String name() { return "capture_requests"; }

    @Override
    public String description() {
        return "Capture HTTP request templates from browser network traffic. "
             + "Use when: you need to understand API request structure, "
             + "save request templates for batch triggering, or analyze network traffic. "
             + "Filters: 'xhr,fetch' (API calls only), 'POST' (method), '2xx' (status). "
             + "Output: list of captured requests with URL, method, headers, body. "
             + "Requires: agent-browser CLI installed.";
    }

    @Override
    public JsonObject inputSchema() {
        JsonObject schema = new JsonObject();
        schema.addProperty("type", "object");

        JsonObject props = new JsonObject();
        props.add("filter", prop("string",
                "Request filter: 'xhr,fetch' (API calls), 'POST' (method), '2xx' (status), "
                + "or leave empty for all requests. Default: 'xhr,fetch'."));
        props.add("save_to_file", prop("string",
                "Optional file path to save captured requests (JSON format). "
                + "If omitted, returns requests in response only."));

        schema.add("properties", props);
        schema.add("required", JsonParser.parseString("[]"));
        return schema;
    }

    @Override
    public String execute(String argumentsJson) {
        JsonObject args = JsonParser.parseString(argumentsJson).getAsJsonObject();
        String filter = args.has("filter") ? args.get("filter").getAsString() : "xhr,fetch";
        String saveToFile = args.has("save_to_file") ? args.get("save_to_file").getAsString() : null;

        // Check if agent-browser is available
        AgentBrowserCli cli = new AgentBrowserCli();
        if (!cli.isAvailable()) {
            return errorJson(
                "agent-browser CLI not found. Install with: "
                + "'npm install -g agent-browser && agent-browser install'."
            );
        }

        try {
            // Capture requests
            List<CapturedRequest> requests = extractionService.captureRequests(filter);

            // Build response
            JsonObject out = new JsonObject();
            out.addProperty("success", true);
            out.addProperty("count", requests.size());
            out.addProperty("filter", filter);

            // Summarize captured requests
            JsonArray requestsArr = new JsonArray();
            for (CapturedRequest req : requests) {
                JsonObject reqObj = new JsonObject();
                reqObj.addProperty("method", req.method());
                reqObj.addProperty("url", req.url());
                reqObj.addProperty("status", req.responseStatus());
                reqObj.addProperty("is_api_call", req.isApiCall());
                reqObj.addProperty("has_body", req.body() != null && !req.body().isEmpty());
                requestsArr.add(reqObj);
            }
            out.add("requests", requestsArr);

            // Save to file if requested
            if (saveToFile != null && !saveToFile.isEmpty()) {
                File outputFile = new File(saveToFile);
                extractionService.saveRequestTemplates(requests, outputFile);
                out.addProperty("saved_to", outputFile.getAbsolutePath());
                out.addProperty("note", 
                    "Captured " + requests.size() + " requests and saved to " + outputFile.getAbsolutePath()
                    + ". Use trigger_apis tool to replay these requests."
                );
            } else {
                out.addProperty("note", 
                    "Captured " + requests.size() + " requests. "
                    + "To save for later use, provide 'save_to_file' parameter."
                );
            }

            return out.toString();

        } catch (Exception e) {
            ctx.logger().warn("[CaptureRequestsTool] 捕获请求失败: %s", e.getMessage());
            return errorJson("Failed to capture requests: " + e.getMessage()
                + ". Make sure agent-browser daemon is running and browser has network traffic.");
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
