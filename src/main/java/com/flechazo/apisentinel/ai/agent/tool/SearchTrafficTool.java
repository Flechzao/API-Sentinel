package com.flechazo.apisentinel.ai.agent.tool;

import com.flechazo.apisentinel.active.TrafficSearcher;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

import java.util.List;
import java.util.Map;

/**
 * Searches Burp's proxy history for traffic matching a domain, path pattern,
 * or parameter name. Lets the Agent reuse auth tokens, common headers, and
 * parameter values from similar-domain traffic when constructing requests for
 * APIs that have no captured traffic.
 */
public class SearchTrafficTool implements AgentTool {

    private final ToolContext ctx;

    public SearchTrafficTool(ToolContext ctx) {
        this.ctx = ctx;
    }

    @Override
    public String name() { return "search_traffic"; }

    @Override
    public boolean isReadOnly() { return true; }

    @Override
    public String description() {
        return "Search Burp proxy history for traffic on the target domain. "
             + "Returns matching requests WITH their auth headers AND response snippets, "
             + "so you can mine already-captured traffic for evidence instead of replaying. "
             + "Reason over the captured requests/responses yourself — what they reveal "
             + "depends on the vuln class. Also reuse auth_headers/parameter values from "
             + "similar endpoints when constructing requests for APIs that have no captured "
             + "traffic. Free, no AI cost.";
    }

    @Override
    public JsonObject inputSchema() {
        JsonObject schema = new JsonObject();
        schema.addProperty("type", "object");
        JsonObject props = new JsonObject();

        JsonObject domainProp = new JsonObject();
        domainProp.addProperty("type", "string");
        domainProp.addProperty("description", "Target domain to search (defaults to current entry's domain)");
        props.add("domain", domainProp);

        JsonObject pathProp = new JsonObject();
        pathProp.addProperty("type", "string");
        pathProp.addProperty("description", "Optional path pattern to narrow results (e.g. '/api/users')");
        props.add("path_pattern", pathProp);

        JsonObject paramProp = new JsonObject();
        paramProp.addProperty("type", "string");
        paramProp.addProperty("description", "Optional parameter name to find values for (e.g. 'userId')");
        props.add("param_name", paramProp);

        schema.add("properties", props);
        return schema;
    }

    @Override
    public String execute(String argumentsJson) {
        if (ctx.montoyaApi() == null) {
            return "{\"error\": \"Burp API not available\"}";
        }

        try {
            var args = com.google.gson.JsonParser.parseString(argumentsJson).getAsJsonObject();
            String domain = args.has("domain") ? args.get("domain").getAsString()
                    : (ctx.entry().getDomain() != null ? ctx.entry().getDomain() : "");
            String pathPattern = args.has("path_pattern") ? args.get("path_pattern").getAsString() : null;
            String paramName = args.has("param_name") ? args.get("param_name").getAsString() : null;

            TrafficSearcher searcher = new TrafficSearcher(ctx.montoyaApi());

            // Entry has no domain of its own: bootstrap from recent proxy traffic.
            // Auto-use only when unambiguous (single recent host); otherwise return
            // the candidates so the Agent picks the right target instead of guessing.
            if (domain == null || domain.isBlank()) {
                List<String> recent = searcher.recentHostPorts(5);
                if (recent.size() == 1) {
                    domain = stripPort(recent.get(0));
                } else {
                    JsonObject o = new JsonObject();
                    o.addProperty("similar_count", 0);
                    o.addProperty("note", "This API has no known domain. " + (recent.isEmpty()
                            ? "Proxy history is empty — capture traffic first."
                            : "Re-call search_traffic with an explicit 'domain' param (pick the target app)."));
                    com.google.gson.JsonArray arr = new com.google.gson.JsonArray();
                    recent.forEach(arr::add);
                    o.add("available_hosts", arr);
                    return o.toString();
                }
            }

            // Find similar traffic templates
            List<TrafficSearcher.TrafficTemplate> templates = searcher.findSimilarTraffic(
                    domain, pathPattern, paramName, 10);

            // Extract auth headers from the first match
            Map<String, String> authHeaders = searcher.extractAuthHeaders(domain);

            // Find param values if requested
            List<String> paramValues = paramName != null && !paramName.isBlank()
                    ? searcher.findParamValues(domain, paramName) : List.of();

            JsonObject out = new JsonObject();
            out.addProperty("domain", domain);
            out.addProperty("similar_count", templates.size());

            JsonArray templatesArr = new JsonArray();
            for (TrafficSearcher.TrafficTemplate t : templates) {
                JsonObject to = new JsonObject();
                to.addProperty("method", t.method());
                to.addProperty("path", t.path());
                to.addProperty("status_code", t.statusCode());
                to.addProperty("content_type", t.contentType());
                JsonObject auth = new JsonObject();
                t.authHeaders().forEach(auth::addProperty);
                to.add("auth_headers", auth);
                if (t.body() != null && !t.body().isEmpty()) {
                    to.addProperty("body_snippet", t.body().length() > 500
                            ? t.body().substring(0, 500) + "..." : t.body());
                }
                if (t.responseSnippet() != null && !t.responseSnippet().isEmpty()) {
                    to.addProperty("response_snippet", t.responseSnippet());
                }
                templatesArr.add(to);
            }
            out.add("templates", templatesArr);

            JsonObject authH = new JsonObject();
            authHeaders.forEach(authH::addProperty);
            out.add("available_auth_headers", authH);

            if (!paramValues.isEmpty()) {
                JsonArray pv = new JsonArray();
                paramValues.forEach(pv::add);
                out.add("param_values", pv);
            }

            out.addProperty("next_step", templates.isEmpty()
                    ? "未找到同域名流量。建议从代码仓库推理参数值，或手动构造请求"
                    : "已找到 " + templates.size() + " 条同域名流量，使用 auth_headers 中的认证信息 + "
                      + "templates 中的参数格式，调用 send_request 构造请求");

            return out.toString();
        } catch (Exception e) {
            return "{\"error\": \"" + escapeJson(e.getMessage()) + "\"}";
        }
    }

    /** Strip a trailing ":port" so the value can be used as a host-only domain match. */
    private static String stripPort(String hostPort) {
        int idx = hostPort.lastIndexOf(':');
        return idx > 0 ? hostPort.substring(0, idx) : hostPort;
    }

    private static String escapeJson(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n");
    }
}