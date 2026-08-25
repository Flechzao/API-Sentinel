package com.flechazo.apisentinel.ai.agent.tool;

import com.flechazo.apisentinel.util.HttpMessageUtils;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import java.util.HashSet;
import java.util.Map;
import java.util.Set;

public class ResponseDiffTool implements AgentTool {

    private final ToolContext ctx;

    public ResponseDiffTool(ToolContext ctx) {
        this.ctx = ctx;
    }

    @Override
    public String name() { return "diff_responses"; }

    @Override
    public String description() {
        return "Structurally compare two HTTP responses (no network requests, free). "
             + "Returns: status code diff, length delta/ratio, Jaccard similarity (3-gram), "
             + "JSON field differences (new/missing keys), and a verdict (IDENTICAL/SIMILAR/"
             + "DIFFERENT). Use this after send_request to programmatically compare responses "
             + "instead of relying on visual inspection.";
    }

    @Override
    public JsonObject inputSchema() {
        JsonObject schema = new JsonObject();
        schema.addProperty("type", "object");
        JsonObject props = new JsonObject();
        props.add("response_a", prop("string", "第一个 HTTP 响应（raw 全文或 body）（必填）"));
        props.add("response_b", prop("string", "第二个 HTTP 响应（raw 全文或 body）（必填）"));
        props.add("mode", prop("string", "对比模式: full|body_only|headers_only（可选，默认 full）"));
        schema.add("properties", props);
        schema.add("required", JsonParser.parseString("[\"response_a\",\"response_b\"]"));
        return schema;
    }

    @Override
    public String execute(String argumentsJson) {
        JsonObject out = new JsonObject();
        try {
            JsonObject args = JsonParser.parseString(argumentsJson).getAsJsonObject();
            String respA = args.get("response_a").getAsString();
            String respB = args.get("response_b").getAsString();
            String mode = args.has("mode") ? args.get("mode").getAsString() : "full";

            int statusA = extractStatus(respA);
            int statusB = extractStatus(respB);
            out.addProperty("status_a", statusA);
            out.addProperty("status_b", statusB);
            out.addProperty("status_diff", statusA != statusB);

            String bodyA = "headers_only".equals(mode) ? "" : extractBody(respA);
            String bodyB = "headers_only".equals(mode) ? "" : extractBody(respB);

            out.addProperty("length_a", bodyA.length());
            out.addProperty("length_b", bodyB.length());
            out.addProperty("length_delta", bodyB.length() - bodyA.length());
            double lengthRatio = Math.max(bodyA.length(), bodyB.length()) > 0
                    ? (double) Math.min(bodyA.length(), bodyB.length()) / Math.max(bodyA.length(), bodyB.length())
                    : 1.0;
            out.addProperty("length_ratio", Math.round(lengthRatio * 100.0) / 100.0);

            double jaccard = computeJaccard(bodyA, bodyB);
            out.addProperty("jaccard_similarity", Math.round(jaccard * 1000.0) / 1000.0);

            // JSON field comparison
            if (!"headers_only".equals(mode)) {
                JsonObject fieldDiffs = compareJsonFields(bodyA, bodyB);
                if (fieldDiffs != null) {
                    out.add("json_field_diff", fieldDiffs);
                }
            }

            // Header diffs
            if (!"body_only".equals(mode)) {
                JsonArray headerDiffs = compareHeaders(respA, respB);
                if (headerDiffs.size() > 0) {
                    out.add("header_diffs", headerDiffs);
                }
            }

            // Verdict
            String verdict;
            if (jaccard >= 0.98 && statusA == statusB) {
                verdict = "IDENTICAL";
            } else if (jaccard >= 0.85 && statusA == statusB) {
                verdict = "SIMILAR";
            } else {
                verdict = "DIFFERENT";
            }
            out.addProperty("verdict", verdict);

        } catch (Exception e) {
            out.addProperty("error", e.getMessage());
        }
        return out.toString();
    }

    static double computeJaccard(String a, String b) {
        if (a.isEmpty() && b.isEmpty()) return 1.0;
        if (a.isEmpty() || b.isEmpty()) return 0.0;
        Set<String> gramsA = trigrams(a);
        Set<String> gramsB = trigrams(b);
        Set<String> intersection = new HashSet<>(gramsA);
        intersection.retainAll(gramsB);
        Set<String> union = new HashSet<>(gramsA);
        union.addAll(gramsB);
        return union.isEmpty() ? 0.0 : (double) intersection.size() / union.size();
    }

    private static Set<String> trigrams(String s) {
        Set<String> set = new HashSet<>();
        String trimmed = s.length() > 10000 ? s.substring(0, 10000) : s;
        for (int i = 0; i <= trimmed.length() - 3; i++) {
            set.add(trimmed.substring(i, i + 3));
        }
        return set;
    }

    private static int extractStatus(String raw) {
        if (raw.startsWith("HTTP/")) {
            int sp1 = raw.indexOf(' ');
            int sp2 = raw.indexOf(' ', sp1 + 1);
            if (sp1 > 0 && sp2 > sp1) {
                try { return Integer.parseInt(raw.substring(sp1 + 1, sp2)); } catch (NumberFormatException ignored) {}
            }
        }
        return 0;
    }

    private static String extractBody(String raw) {
        String body = HttpMessageUtils.bodyOf(raw);
        return body != null ? body : raw;
    }

    private static JsonObject compareJsonFields(String bodyA, String bodyB) {
        try {
            JsonElement elA = JsonParser.parseString(bodyA);
            JsonElement elB = JsonParser.parseString(bodyB);
            if (!elA.isJsonObject() || !elB.isJsonObject()) return null;

            Set<String> keysA = elA.getAsJsonObject().keySet();
            Set<String> keysB = elB.getAsJsonObject().keySet();

            Set<String> newInB = new HashSet<>(keysB);
            newInB.removeAll(keysA);
            Set<String> missingInB = new HashSet<>(keysA);
            missingInB.removeAll(keysB);

            if (newInB.isEmpty() && missingInB.isEmpty()) return null;

            JsonObject diff = new JsonObject();
            if (!newInB.isEmpty()) {
                JsonArray arr = new JsonArray();
                newInB.forEach(arr::add);
                diff.add("new_in_b", arr);
            }
            if (!missingInB.isEmpty()) {
                JsonArray arr = new JsonArray();
                missingInB.forEach(arr::add);
                diff.add("missing_from_b", arr);
            }
            return diff;
        } catch (Exception e) {
            return null;
        }
    }

    private static JsonArray compareHeaders(String rawA, String rawB) {
        JsonArray diffs = new JsonArray();
        Map<String, String> headersA = parseHeaders(rawA);
        Map<String, String> headersB = parseHeaders(rawB);

        Set<String> allKeys = new HashSet<>(headersA.keySet());
        allKeys.addAll(headersB.keySet());

        for (String key : allKeys) {
            String valA = headersA.get(key);
            String valB = headersB.get(key);
            if (valA == null || valB == null || !valA.equals(valB)) {
                JsonObject d = new JsonObject();
                d.addProperty("name", key);
                d.addProperty("a", valA != null ? valA : "(absent)");
                d.addProperty("b", valB != null ? valB : "(absent)");
                diffs.add(d);
                if (diffs.size() >= 10) break;
            }
        }
        return diffs;
    }

    private static Map<String, String> parseHeaders(String raw) {
        Map<String, String> map = new java.util.LinkedHashMap<>();
        String headerSection = HttpMessageUtils.headerSection(raw);
        if (headerSection == null) return map;
        String[] lines = headerSection.split("\\r?\\n");
        for (int i = 1; i < lines.length; i++) {
            int colon = lines[i].indexOf(':');
            if (colon > 0) {
                String name = lines[i].substring(0, colon).trim().toLowerCase();
                String value = lines[i].substring(colon + 1).trim();
                map.put(name, value);
            }
        }
        return map;
    }

    private static JsonObject prop(String type, String desc) {
        JsonObject p = new JsonObject();
        p.addProperty("type", type);
        p.addProperty("description", desc);
        return p;
    }
}
