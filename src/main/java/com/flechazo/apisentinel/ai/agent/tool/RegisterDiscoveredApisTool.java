package com.flechazo.apisentinel.ai.agent.tool;

import com.flechazo.apisentinel.browser.BrowserService;
import com.flechazo.apisentinel.browser.DiscoveredApi;
import com.flechazo.apisentinel.repository.ApiRepository;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import java.util.ArrayList;
import java.util.List;

/**
 * Agent tool for registering browser-discovered APIs to the analysis queue.
 *
 * <p>After browser_discover finds new APIs, use this tool to add them to the
 * repository so they appear in the API table and can be analyzed.
 */
public class RegisterDiscoveredApisTool implements AgentTool {

    private final ToolContext ctx;
    private final BrowserService browserService;
    private final ApiRepository repository;

    public RegisterDiscoveredApisTool(ToolContext ctx, BrowserService browserService, ApiRepository repository) {
        this.ctx = ctx;
        this.browserService = browserService;
        this.repository = repository;
    }

    @Override
    public String name() { return "register_discovered_apis"; }

    @Override
    public String description() {
        return "Register browser-discovered APIs to the analysis queue. "
             + "After browser_discover finds new APIs, use this tool to add them to the repository. "
             + "They will appear in the API table and can be analyzed like any other endpoint.";
    }

    @Override
    public JsonObject inputSchema() {
        JsonObject schema = new JsonObject();
        schema.addProperty("type", "object");
        JsonObject props = new JsonObject();

        JsonObject apiSchema = new JsonObject();
        apiSchema.addProperty("type", "object");
        JsonObject apiProps = new JsonObject();
        apiProps.add("method", prop("string", "HTTP method (GET, POST, etc.)"));
        apiProps.add("path", prop("string", "API path (e.g., /api/users)"));
        apiSchema.add("properties", apiProps);

        JsonObject apisProp = new JsonObject();
        apisProp.addProperty("type", "array");
        apisProp.add("items", apiSchema);
        apisProp.addProperty("description", "List of APIs to register (required)");
        props.add("apis", apisProp);

        schema.add("properties", props);
        schema.add("required", JsonParser.parseString("[\"apis\"]"));
        return schema;
    }

    @Override
    public String execute(String argumentsJson) {
        if (browserService == null) {
            return errorJson("Browser service not available.");
        }

        JsonObject args = JsonParser.parseString(argumentsJson).getAsJsonObject();
        JsonArray apisArr = args.has("apis") ? args.getAsJsonArray("apis") : null;

        if (apisArr == null || apisArr.isEmpty()) {
            return errorJson("apis array is required and must not be empty");
        }

        List<DiscoveredApi> apis = new ArrayList<>();
        for (JsonElement elem : apisArr) {
            JsonObject apiObj = elem.getAsJsonObject();
            String method = apiObj.has("method") ? apiObj.get("method").getAsString() : "GET";
            String path = apiObj.has("path") ? apiObj.get("path").getAsString() : null;
            if (path != null && !path.isEmpty()) {
                apis.add(new DiscoveredApi(method, path, "manual", "", "", ""));
            }
        }

        try {
            int registered = browserService.registerDiscoveredApis(apis);

            JsonObject out = new JsonObject();
            out.addProperty("success", true);
            out.addProperty("registered_count", registered);
            out.addProperty("submitted_count", apis.size());
            out.addProperty("skipped_existing", apis.size() - registered);

            if (registered > 0) {
                out.addProperty("note", String.format(
                        "Registered %d new APIs. They now appear in the API table and can be analyzed. "
                        + "Use send_request or trigger AI analysis on them.",
                        registered));
            } else {
                out.addProperty("note", "All submitted APIs already exist in the repository.");
            }

            return out.toString();

        } catch (Exception e) {
            return errorJson("Registration failed: " + e.getMessage());
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
