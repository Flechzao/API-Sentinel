package com.flechazo.apisentinel.ai.agent.tool;

import com.flechazo.apisentinel.auth.SessionDiscovery;
import com.flechazo.apisentinel.auth.SessionInfo;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import java.util.List;

/**
 * Lets the agent inspect how many distinct authenticated sessions are available
 * for a domain before running auth-bypass tests. Read-only (no requests sent).
 */
public class ListSessionsTool implements AgentTool {

    private final ToolContext ctx;

    public ListSessionsTool(ToolContext ctx) {
        this.ctx = ctx;
    }

    @Override
    public String name() { return "list_sessions"; }

    @Override
    public String description() {
        return "List distinct authenticated sessions discovered in Burp proxy history for a domain. "
             + "Returns each session's cookie keys, auth headers and request count, so you can tell "
             + "whether enough sessions exist for authorization/IDOR testing before calling test_auth_bypass. "
             + "Read-only, sends no requests, free.";
    }

    @Override
    public JsonObject inputSchema() {
        JsonObject schema = new JsonObject();
        schema.addProperty("type", "object");
        JsonObject props = new JsonObject();
        JsonObject domain = new JsonObject();
        domain.addProperty("type", "string");
        domain.addProperty("description",
                "Target host (with or without port). Omit to use the current API entry's domain.");
        props.add("domain", domain);
        schema.add("properties", props);
        return schema;
    }

    @Override
    public String execute(String argumentsJson) {
        if (ctx.montoyaApi() == null) {
            return "{\"error\": \"Burp API not available\"}";
        }
        String domain = null;
        try {
            JsonObject args = JsonParser.parseString(argumentsJson).getAsJsonObject();
            if (args.has("domain") && !args.get("domain").getAsString().isBlank()) {
                domain = args.get("domain").getAsString();
            }
        } catch (Exception ignored) {}

        if (domain == null && ctx.entry() != null) {
            domain = ctx.entry().getDomain();
        }
        if (domain == null || domain.isBlank()) {
            return "{\"error\": \"No domain provided and current entry has no domain\"}";
        }

        SessionDiscovery discovery = new SessionDiscovery(ctx.montoyaApi());
        List<SessionInfo> sessions = discovery.discoverDomainSessions(domain);

        JsonObject out = new JsonObject();
        out.addProperty("domain", domain);
        out.addProperty("sessionCount", sessions.size());
        JsonArray arr = new JsonArray();
        int idx = 0;
        for (SessionInfo s : sessions) {
            JsonObject so = new JsonObject();
            so.addProperty("index", idx++);
            so.addProperty("fingerprint", s.getFingerprint());
            so.addProperty("requestCount", s.getRequests().size());
            JsonArray cookieKeys = new JsonArray();
            s.getCookieMap().keySet().forEach(cookieKeys::add);
            so.add("cookieKeys", cookieKeys);
            JsonArray headerKeys = new JsonArray();
            s.getAuthHeaders().keySet().forEach(headerKeys::add);
            so.add("authHeaderKeys", headerKeys);
            arr.add(so);
        }
        out.add("sessions", arr);
        out.addProperty("sufficientForAuthBypass", sessions.size() >= 2);
        if (sessions.size() < 2) {
            out.addProperty("hint",
                    "Fewer than 2 sessions. Ask the user to browse the target with a second account "
                  + "through the Burp proxy, then re-run.");
        }
        return out.toString();
    }
}
