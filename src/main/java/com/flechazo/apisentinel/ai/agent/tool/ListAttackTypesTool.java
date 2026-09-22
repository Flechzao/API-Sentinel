package com.flechazo.apisentinel.ai.agent.tool;

import com.flechazo.apisentinel.detection.AttackType;
import com.flechazo.apisentinel.detection.PayloadLibrary;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

import java.util.List;
import java.util.Map;

/**
 * list_attack_types — 列出可用攻击类型和 Payload
 *
 * 允许 Agent 查询系统支持的攻击类型分类和对应 Payload 库。
 * 支持以下查询模式：
 *   1. 无参数：列出所有攻击类型摘要
 *   2. attack_type：获取指定类型的详细信息和 Payload
 *   3. severity：按严重性过滤
 *   4. owasp_top10：只列出 OWASP API Top 10
 *   5. search：搜索 Payload
 *
 * 零 LLM 调用，纯本地查询。
 */
public class ListAttackTypesTool implements AgentTool {

    private final ToolContext ctx;

    public ListAttackTypesTool(ToolContext ctx) {
        this.ctx = ctx;
    }

    @Override
    public String name() { return "list_attack_types"; }

    @Override
    public String description() {
        return "List available attack types and their payloads from the built-in library. "
             + "Supports 27 attack categories with 150+ payloads covering OWASP API Security Top 10 "
             + "and common web vulnerabilities. Zero LLM cost — pure local lookup. "
             + "Use this to plan which payloads to send via send_request or generate_payloads.";
    }

    @Override
    public JsonObject inputSchema() {
        JsonObject schema = new JsonObject();
        schema.addProperty("type", "object");
        JsonObject props = new JsonObject();

        JsonObject attackType = new JsonObject();
        attackType.addProperty("type", "string");
        attackType.addProperty("description", "Specific attack type ID to get details (e.g. 'BOLA', 'SQL_INJECTION'). Omit to list all.");
        props.add("attack_type", attackType);

        JsonObject severity = new JsonObject();
        severity.addProperty("type", "string");
        severity.addProperty("description", "Filter by severity: CRITICAL, HIGH, MEDIUM, LOW");
        props.add("severity", severity);

        JsonObject owaspOnly = new JsonObject();
        owaspOnly.addProperty("type", "boolean");
        owaspOnly.addProperty("description", "Only show OWASP API Security Top 10 types");
        props.add("owasp_top10_only", owaspOnly);

        JsonObject search = new JsonObject();
        search.addProperty("type", "string");
        search.addProperty("description", "Search keyword to find matching payloads");
        props.add("search", search);

        JsonObject limit = new JsonObject();
        limit.addProperty("type", "integer");
        limit.addProperty("description", "Max number of payloads to return per type (default: 10)");
        props.add("payload_limit", limit);

        schema.add("properties", props);
        return schema;
    }

    @Override
    public String execute(String argumentsJson) {
        JsonObject args = parseArgs(argumentsJson);
        String attackTypeId = getString(args, "attack_type");
        String severity = getString(args, "severity");
        boolean owaspOnly = getBoolean(args, "owasp_top10_only");
        String search = getString(args, "search");
        int payloadLimit = getInt(args, "payload_limit", 10);

        JsonObject out = new JsonObject();

        // Search mode
        if (search != null && !search.isEmpty()) {
            return executeSearch(search, payloadLimit);
        }

        // Single type detail
        if (attackTypeId != null && !attackTypeId.isEmpty()) {
            return executeDetail(attackTypeId, payloadLimit);
        }

        // List mode (with optional filters)
        return executeList(severity, owaspOnly);
    }

    private String executeList(String severityFilter, boolean owaspOnly) {
        JsonObject out = new JsonObject();

        List<String> typeIds;
        if (owaspOnly) {
            typeIds = AttackType.getOwaspApiTop10();
        } else if (severityFilter != null && !severityFilter.isEmpty()) {
            typeIds = AttackType.getBySeverity(severityFilter.toUpperCase());
        } else {
            typeIds = List.copyOf(AttackType.getAll().keySet());
        }

        JsonArray types = new JsonArray();
        for (String id : typeIds) {
            AttackType.AttackTypeInfo info = AttackType.get(id);
            if (info == null) continue;

            JsonObject t = new JsonObject();
            t.addProperty("id", info.id());
            t.addProperty("name", info.name());
            t.addProperty("description", info.description());
            t.addProperty("severity", info.severity());
            t.addProperty("owasp_mapping", info.owaspMapping());
            t.addProperty("payload_count", PayloadLibrary.get(id).size());
            types.add(t);
        }

        out.addProperty("success", true);
        out.addProperty("total", typeIds.size());
        out.addProperty("total_payloads", PayloadLibrary.totalCount());
        if (owaspOnly) out.addProperty("filter", "OWASP API Top 10");
        if (severityFilter != null) out.addProperty("filter", "severity=" + severityFilter);
        out.add("attack_types", types);
        out.addProperty("hint", "Use attack_type parameter to get detailed info and payloads for a specific type");
        return out.toString();
    }

    private String executeDetail(String attackTypeId, int payloadLimit) {
        JsonObject out = new JsonObject();
        AttackType.AttackTypeInfo info = AttackType.get(attackTypeId);

        if (info == null) {
            out.addProperty("success", false);
            out.addProperty("error", "Unknown attack type: " + attackTypeId);
            out.add("available_types", toJsonArray(List.copyOf(AttackType.getAll().keySet())));
            return out.toString();
        }

        out.addProperty("success", true);
        out.addProperty("id", info.id());
        out.addProperty("name", info.name());
        out.addProperty("description", info.description());
        out.addProperty("severity", info.severity());
        out.addProperty("owasp_mapping", info.owaspMapping());

        JsonArray detectors = new JsonArray();
        for (String d : info.detectors()) detectors.add(d);
        out.add("available_tools", detectors);

        JsonArray categories = new JsonArray();
        for (String c : info.payloadCategories()) categories.add(c);
        out.add("payload_categories", categories);

        // Payloads
        List<PayloadLibrary.Payload> payloads = PayloadLibrary.get(attackTypeId);
        JsonArray payloadArr = new JsonArray();
        int limit = Math.min(payloads.size(), payloadLimit);
        for (int i = 0; i < limit; i++) {
            PayloadLibrary.Payload p = payloads.get(i);
            JsonObject po = new JsonObject();
            po.addProperty("payload", p.value());
            po.addProperty("name", p.name());
            po.addProperty("description", p.description());
            payloadArr.add(po);
        }
        out.add("payloads", payloadArr);
        out.addProperty("payload_total", payloads.size());
        out.addProperty("payload_shown", limit);
        if (payloads.size() > payloadLimit) {
            out.addProperty("hint", "Increase payload_limit to see more, or use search parameter");
        }

        out.addProperty("next_step", "Use send_request to send these payloads, or generate_payloads for AI-generated variants");
        return out.toString();
    }

    private String executeSearch(String keyword, int payloadLimit) {
        JsonObject out = new JsonObject();
        List<PayloadLibrary.Payload> results = PayloadLibrary.search(keyword);

        out.addProperty("success", true);
        out.addProperty("keyword", keyword);
        out.addProperty("total_matches", results.size());

        JsonArray arr = new JsonArray();
        int limit = Math.min(results.size(), payloadLimit);
        for (int i = 0; i < limit; i++) {
            PayloadLibrary.Payload p = results.get(i);
            JsonObject po = new JsonObject();
            po.addProperty("payload", p.value());
            po.addProperty("name", p.name());
            po.addProperty("description", p.description());
            arr.add(po);
        }
        out.add("results", arr);
        out.addProperty("shown", limit);
        return out.toString();
    }

    // ==================== Helper Methods ====================

    private JsonObject parseArgs(String json) {
        if (json == null || json.isBlank()) return new JsonObject();
        try {
            return com.google.gson.JsonParser.parseString(json).getAsJsonObject();
        } catch (Exception e) {
            return new JsonObject();
        }
    }

    private String getString(JsonObject obj, String key) {
        if (obj.has(key) && !obj.get(key).isJsonNull()) {
            return obj.get(key).getAsString();
        }
        return null;
    }

    private boolean getBoolean(JsonObject obj, String key) {
        if (obj.has(key) && !obj.get(key).isJsonNull()) {
            return obj.get(key).getAsBoolean();
        }
        return false;
    }

    private int getInt(JsonObject obj, String key, int defaultValue) {
        if (obj.has(key) && !obj.get(key).isJsonNull()) {
            try {
                return obj.get(key).getAsInt();
            } catch (Exception e) {
                return defaultValue;
            }
        }
        return defaultValue;
    }

    private JsonArray toJsonArray(List<String> list) {
        JsonArray arr = new JsonArray();
        for (String s : list) arr.add(s);
        return arr;
    }
}
