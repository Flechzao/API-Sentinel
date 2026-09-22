package com.flechazo.apisentinel.ai.agent.tool;

import com.flechazo.apisentinel.codeindex.parser.RouteEntry;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

import java.util.List;

public class SearchSourceCodeTool implements AgentTool {

    private final ToolContext ctx;
    private String lastSourceCode = "";

    public SearchSourceCodeTool(ToolContext ctx) {
        this.ctx = ctx;
    }

    public String getLastSourceCode() { return lastSourceCode; }

    @Override
    public String name() { return "search_source_code"; }

    @Override
    public boolean isReadOnly() { return true; }

    @Override
    public String description() {
        return "Search indexed source code repositories for route handlers matching the API endpoint. "
             + "Returns matched source files, line numbers, and code snippets. Free, no AI cost.";
    }

    @Override
    public JsonObject inputSchema() {
        JsonObject schema = new JsonObject();
        schema.addProperty("type", "object");
        JsonObject props = new JsonObject();
        JsonObject pathProp = new JsonObject();
        pathProp.addProperty("type", "string");
        pathProp.addProperty("description", "API path to search for. Defaults to current entry's path if empty.");
        props.add("path", pathProp);
        schema.add("properties", props);
        return schema;
    }

    @Override
    public String execute(String argumentsJson) {
        if (ctx.codeIndexService() == null || ctx.codeRepos() == null || ctx.codeRepos().isEmpty()) {
            return "{\"found\": false, \"message\": \"No source code repositories configured.\"}";
        }

        String searchPath = ctx.entry().getApiPath();
        try {
            var parsed = com.google.gson.JsonParser.parseString(argumentsJson).getAsJsonObject();
            if (parsed.has("path") && !parsed.get("path").getAsString().isEmpty()) {
                searchPath = parsed.get("path").getAsString();
            }
        } catch (Exception ignored) {}

        try {
            List<RouteEntry> routes = ctx.codeIndexService().findByPathAndDomain(
                    searchPath, ctx.entry().getDomain(), ctx.codeRepos());

            JsonObject result = new JsonObject();
            result.addProperty("found", !routes.isEmpty());
            result.addProperty("matches", routes.size());

            JsonArray routesArr = new JsonArray();
            StringBuilder allSource = new StringBuilder();
            for (RouteEntry r : routes) {
                JsonObject ro = new JsonObject();
                ro.addProperty("file", r.sourceFile().toString());
                ro.addProperty("line", r.startLine());
                ro.addProperty("method", r.httpMethod());
                ro.addProperty("path_pattern", r.routePattern());
                ro.addProperty("handler", r.className() + "." + r.methodName());
                String src = ctx.codeIndexService().getSourceCode(r);
                if (src != null && !src.isEmpty()) {
                    ro.addProperty("source_snippet", truncate(src, 6000));
                    allSource.append("// ").append(r.sourceFile()).append(":").append(r.startLine()).append("\n");
                    allSource.append(src).append("\n\n");
                }
                routesArr.add(ro);
            }
            result.add("routes", routesArr);
            lastSourceCode = allSource.toString();
            return result.toString();
        } catch (Exception e) {
            return "{\"found\": false, \"error\": \"" + escapeJson(e.getMessage()) + "\"}";
        }
    }

    private static String truncate(String s, int max) {
        return s.length() <= max ? s : s.substring(0, max) + "\n...[truncated]";
    }

    private static String escapeJson(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n");
    }
}
