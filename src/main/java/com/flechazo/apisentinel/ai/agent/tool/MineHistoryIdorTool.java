package com.flechazo.apisentinel.ai.agent.tool;

import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;
import com.flechazo.apisentinel.auth.SessionDiscovery;
import com.flechazo.apisentinel.auth.SessionInfo;
import com.flechazo.apisentinel.model.ApiEntry;
import com.flechazo.apisentinel.util.UrlUtils;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Deterministic history-mining IDOR detector — scans the already-captured proxy
 * history (no replay, no auth needed) for cross-account access.
 *
 * <p>Principle: if two <b>different auth-fingerprint sessions</b> request the
 * <b>same resource</b> and get the <b>same response</b> (or a response whose
 * owner field belongs to one account), that's an IDOR — when access control
 * works, the second session gets its own (different) data or is denied.
 *
 * <p>Reports findings as <b>SUSPECTED</b>, never confirmed: the auth fingerprint
 * can't prove two sessions are different <i>users</i> (same user's multiple
 * tabs share identity but differ in per-tab tokens), so a human/agent must
 * confirm the two sessions are genuinely different accounts. When an
 * {@code owner_field} is supplied and matches across sessions, that's the
 * strongest signal but still requires the two-session-identity check.
 *
 * <p>This is the path that works for bigfish/ctoken+signature endpoints where
 * replay-based IDOR testing (send_request/test_auth_bypass) can't authenticate
 * — the proof is already in the captured history.
 */
public class MineHistoryIdorTool implements AgentTool {

    private final ToolContext ctx;

    public MineHistoryIdorTool(ToolContext ctx) {
        this.ctx = ctx;
    }

    @Override
    public String name() { return "mine_history_idor"; }

    @Override
    public boolean isReadOnly() { return true; }

    @Override
    public String description() {
        return "Deterministically mine captured proxy history for IDOR/BOLA authorization bypass — NO replay, "
             + "NO authentication needed (works even when the endpoint uses ctoken+signature auth that "
             + "send_request can't replicate). Enhanced with auto owner-field detection, structural IDOR "
             + "signals, multi-format ID extraction (numeric/UUID/ULID/Snowflake/MongoDB), and confidence "
             + "scoring (0-100). Groups requests to the endpoint by resource id, finds the same resource "
             + "requested by ≥2 different auth sessions, and compares their responses. Pass resource_id_param "
             + "(e.g. 'innerPeeringId') or let auto-detection find IDs. Pass owner_field (e.g. 'uid') or "
             + "let auto-detection scan for common patterns (userId/accountId/ownerId/etc). Output includes "
             + "confidence score and is SUSPECTED — confirm two sessions are different accounts before "
             + "treating as confirmed. Free, no AI cost.";
    }

    @Override
    public JsonObject inputSchema() {
        JsonObject schema = new JsonObject();
        schema.addProperty("type", "object");
        JsonObject props = new JsonObject();
        props.add("resource_id_param", prop("string",
                "Optional: the param/field that identifies the resource — a query/body param name "
                + "(e.g. 'innerPeeringId', 'orderId') or a path segment. If omitted, numeric/UUID "
                + "path segments are used. Essential for RPC-gateway APIs where the resource id is in the body."));
        props.add("owner_field", prop("string",
                "Optional: a JSON field in the response naming the resource's owner "
                + "(e.g. 'uid', 'owner', 'userId', 'accountId'). When given, the tool checks whether "
                + "different sessions see the SAME owner for the same resource (strongest IDOR signal)."));
        schema.add("properties", props);
        return schema;
    }

    private static JsonObject prop(String type, String desc) {
        JsonObject p = new JsonObject();
        p.addProperty("type", type);
        p.addProperty("description", desc);
        return p;
    }

    @Override
    public String execute(String argumentsJson) {
        ApiEntry entry = ctx.entry();
        if (entry == null) {
            return err("mine_history_idor needs a target endpoint — run it from an API entry's analysis.");
        }
        if (ctx.montoyaApi() == null) {
            return err("Burp API unavailable.");
        }
        String resourceIdParam = null;
        String ownerField = null;
        try {
            JsonObject args = JsonParser.parseString(argumentsJson).getAsJsonObject();
            resourceIdParam = args.has("resource_id_param") && !args.get("resource_id_param").isJsonNull()
                    ? args.get("resource_id_param").getAsString() : null;
            ownerField = args.has("owner_field") && !args.get("owner_field").isJsonNull()
                    ? args.get("owner_field").getAsString() : null;
        } catch (Exception ignored) {}

        List<SessionInfo> sessions = new SessionDiscovery(ctx.montoyaApi()).discoverSessions(entry);
        JsonObject out = new JsonObject();
        out.addProperty("endpoint", entry.getApiPath());
        out.addProperty("sessions_found", sessions.size());
        if (sessions.size() < 2) {
            out.addProperty("result", "fewer than 2 distinct auth sessions hit this endpoint — "
                    + "cannot cross-compare. Capture traffic from a second account, or widen to "
                    + "domain-wide sessions.");
            return out.toString();
        }

        // resourceId → captured (sessionFingerprint, request, responseBody, statusCode)
        Map<String, List<Captured>> byResource = new LinkedHashMap<>();
        for (SessionInfo sess : sessions) {
            String fp = sess.getFingerprint();
            for (ProxyHttpRequestResponse item : sess.getRequests()) {
                HttpRequest req = item.finalRequest();
                String rid = extractResourceId(req, resourceIdParam);
                if (rid == null || rid.isEmpty()) continue;
                HttpResponse resp = item.response();
                int code = resp != null ? resp.statusCode() : 0;
                String body = resp != null ? resp.bodyToString() : "";
                byResource.computeIfAbsent(rid, k -> new ArrayList<>())
                        .add(new Captured(fp, req, body, code));
            }
        }

        JsonArray findings = new JsonArray();
        int suspect = 0, safe = 0, inconclusive = 0;
        int emitted = 0;
        for (Map.Entry<String, List<Captured>> e : byResource.entrySet()) {
            String rid = e.getKey();
            List<Captured> all = e.getValue();
            // distinct session fingerprints for this resource
            Set<String> fps = new HashSet<>();
            for (Captured c : all) fps.add(c.sessionFp);
            if (fps.size() < 2) continue; // only one session hit this resource — nothing to compare

            for (int i = 0; i < all.size() && emitted < 30; i++) {
                for (int j = i + 1; j < all.size() && emitted < 30; j++) {
                    Captured a = all.get(i);
                    Captured b = all.get(j);
                    if (a.sessionFp.equals(b.sessionFp)) continue; // same session — not a cross-session pair
                    JsonObject f = compare(rid, a, b, ownerField);
                    String verdict = f.get("verdict").getAsString();
                    if ("SUSPECTED_IDOR".equals(verdict)) suspect++;
                    else if ("SAFE".equals(verdict)) safe++;
                    else inconclusive++;
                    findings.add(f);
                    emitted++;
                }
            }
        }

        out.addProperty("resource_groups_compared", byResource.size());
        out.addProperty("suspected_idor", suspect);
        out.addProperty("safe", safe);
        out.addProperty("inconclusive", inconclusive);
        out.add("findings", findings);
        out.addProperty("note", suspect > 0
                ? "发现疑似越权：不同会话请求同一资源拿到相同/同归属数据。需人工确认两个会话是不同身份"
                + "（非同一用户多 tab）后才能定为 confirmed。"
                : "未发现跨会话同资源同响应的越权迹象。");
        return out.toString();
    }

    /** Common owner/identity fields that auto-detection scans for */
    private static final String[] AUTO_OWNER_FIELDS = {
            "userId", "user_id", "uid", "ownerId", "owner_id", "owner",
            "accountId", "account_id", "accountId", "customerId", "customer_id",
            "memberId", "member_id", "tenantId", "tenant_id",
            "createdBy", "created_by", "authorId", "author_id"
    };

    /**
     * Auto-detect owner field from response body by scanning for common patterns.
     * Returns the first matching field name, or null if none found.
     */
    private static String autoDetectOwnerField(String body) {
        if (body == null || body.isEmpty()) return null;
        for (String field : AUTO_OWNER_FIELDS) {
            // Check JSON patterns: "field":"value" or "field": 123
            if (Pattern.compile("\"" + Pattern.quote(field) + "\"\\s*:\\s*\"?[^\",}\\s]+").matcher(body).find()) {
                return field;
            }
        }
        return null;
    }

    private JsonObject compare(String rid, Captured a, Captured b, String ownerField) {
        JsonObject f = new JsonObject();
        f.addProperty("session_a_fingerprint", a.sessionFp);
        f.addProperty("session_b_fingerprint", b.sessionFp);
        f.addProperty("session_a_status", a.statusCode);
        f.addProperty("session_b_status", b.statusCode);

        boolean aDenied = a.statusCode == 401 || a.statusCode == 403 || a.statusCode == 404;
        boolean bDenied = b.statusCode == 401 || b.statusCode == 403 || b.statusCode == 404;
        boolean aOk = a.statusCode >= 200 && a.statusCode < 300;
        boolean bOk = b.statusCode >= 200 && b.statusCode < 300;
        String verdict, reason;
        int confidence = 0; // 0-100 confidence score

        if ((aOk && bDenied) || (bOk && aDenied)) {
            verdict = "SAFE";
            reason = "一个会话 200、另一个 401/403/404 — 访问控制正常拦截";
            confidence = 90;
        } else if (aOk && bOk) {
            double sim = similarity(a.body, b.body);
            f.addProperty("response_similarity", String.format("%.2f", sim));

            // Auto-detect owner field if not provided
            String effectiveOwnerField = ownerField;
            if (effectiveOwnerField == null) {
                effectiveOwnerField = autoDetectOwnerField(a.body);
                if (effectiveOwnerField == null) {
                    effectiveOwnerField = autoDetectOwnerField(b.body);
                }
                if (effectiveOwnerField != null) {
                    f.addProperty("auto_detected_owner_field", effectiveOwnerField);
                }
            }

            String ownerA = extractField(a.body, effectiveOwnerField);
            String ownerB = extractField(b.body, effectiveOwnerField);
            if (effectiveOwnerField != null) {
                if (ownerA != null) f.addProperty("session_a_owner", ownerA);
                if (ownerB != null) f.addProperty("session_b_owner", ownerB);
                if (ownerA != null && ownerB != null && ownerA.equals(ownerB)) {
                    verdict = "SUSPECTED_IDOR";
                    reason = "两个不同会话请求同一资源(id=" + rid + ")，响应的 " + effectiveOwnerField
                            + " 相同(" + ownerA + ") — 跨会话看到同一账号数据，疑似越权";
                    confidence = sim >= 0.9 ? 85 : 70; // high confidence when owner matches + high similarity
                } else if (ownerA != null && ownerB != null) {
                    verdict = "SAFE";
                    reason = "两会话响应的 " + effectiveOwnerField + " 不同(" + ownerA + " vs " + ownerB + ") — 各看各的";
                    confidence = 85;
                } else {
                    // owner field requested but not found — fall back to similarity
                    if (sim >= 0.85) {
                        verdict = "SUSPECTED_IDOR";
                        reason = "两会话请求同一资源(id=" + rid + ")，响应高度相似(" + pct(sim)
                                + ")；未找到 " + effectiveOwnerField + " 字段，疑似越权";
                        confidence = 60;
                    } else {
                        verdict = "SAFE";
                        reason = "响应差异大，各会话看各自数据";
                        confidence = 75;
                    }
                }
            } else {
                if (sim >= 0.85) {
                    verdict = "SUSPECTED_IDOR";
                    reason = "两个不同会话请求同一资源(id=" + rid + ")，响应高度相似(" + pct(sim)
                            + ") — 疑似越权(需确认两会话非同一用户多 tab)";
                    // Boost confidence if we also detect a structural IDOR signal
                    if (hasStructuralIdorSignal(a.body, b.body)) {
                        confidence = 65;
                        reason += "；检测到结构化越权信号（响应含同资源 ID 引用）";
                    } else {
                        confidence = 50;
                    }
                } else {
                    verdict = "SAFE";
                    reason = "响应差异大，各会话看各自数据";
                    confidence = 75;
                }
            }
        } else {
            verdict = "INCONCLUSIVE";
            reason = "状态码非典型(非2xx/401/403/404)：" + a.statusCode + "/" + b.statusCode;
            confidence = 20;
        }
        f.addProperty("verdict", verdict);
        f.addProperty("reason", reason);
        f.addProperty("confidence", confidence);
        f.addProperty("session_a_request", a.req.url());
        f.addProperty("session_b_request", b.req.url());
        f.addProperty("session_a_response_snippet", snippet(a.body));
        f.addProperty("session_b_response_snippet", snippet(b.body));
        return f;
    }

    /**
     * Check for structural IDOR signals: when both responses reference the same
     * resource ID (stronger than just text similarity).
     */
    private static boolean hasStructuralIdorSignal(String bodyA, String bodyB) {
        if (bodyA == null || bodyB == null) return false;
        // Extract all ID-like values from both responses and check for overlap
        Set<String> idsA = extractAllIds(bodyA);
        Set<String> idsB = extractAllIds(bodyB);
        if (idsA.isEmpty() || idsB.isEmpty()) return false;
        // If both responses share 2+ IDs (beyond the resource ID itself), that's a structural signal
        long shared = 0;
        for (String id : idsA) {
            if (idsB.contains(id)) shared++;
            if (shared >= 2) return true;
        }
        return false;
    }

    /** Extract all ID-like values from a JSON body. */
    private static Set<String> extractAllIds(String body) {
        Set<String> ids = new HashSet<>();
        if (body == null) return ids;
        // Match quoted strings that look like IDs (numeric 2+, UUID, hex 24+)
        Matcher m = Pattern.compile("\"(?:\\w*(?:id|Id|ID|_id))\"\\s*:\\s*\"?([0-9a-fA-F-]{8,})\"?").matcher(body);
        while (m.find() && ids.size() < 20) {
            ids.add(m.group(1));
        }
        return ids;
    }

    // ---- resource id extraction ----

    private static String extractResourceId(HttpRequest req, String paramName) {
        String url = req.url();
        String query = UrlUtils.extractQueryString(url);
        if (paramName != null && query != null && !query.isBlank()) {
            String v = extractFormValue(query, paramName);
            if (v != null) return v;
        }
        String body = req.bodyToString();
        if (paramName != null && body != null && !body.isBlank()) {
            String v = extractJsonOrFormValue(body, paramName);
            if (v == null) v = extractJsonOrFormValue(urlDecode(body), paramName);
            if (v != null) return v;
        }
        // Enhanced: also look for numeric/UUID resource IDs in the request body
        // even without an explicit paramName (for JSON APIs with {id: "xxx"} patterns)
        if (body != null && !body.isBlank()) {
            String bodyRid = extractIdFromBody(body);
            if (bodyRid != null) return bodyRid;
        }
        String path = UrlUtils.extractPath(url);
        // Enhanced ID patterns: numeric, UUID, ULID, NanoID, Snowflake
        for (String seg : path.split("/")) {
            if (isResourceId(seg)) return seg;
        }
        return path; // fallback: group by the whole path
    }

    /** Enhanced: check if a path segment looks like a resource identifier. */
    private static boolean isResourceId(String seg) {
        if (seg == null || seg.isEmpty()) return false;
        // Numeric ID (2+ digits, e.g. 123, 1234567890)
        if (seg.matches("\\d{2,}")) return true;
        // UUID: 8-4-4-4-12 hex
        if (seg.matches("[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")) return true;
        // ULID: 26 chars Crockford Base32
        if (seg.matches("[0-9A-HJKMNP-TV-Z]{26}")) return true;
        // Snowflake-like long numeric ID (16+ digits, e.g. Twitter IDs)
        if (seg.matches("\\d{16,}")) return true;
        // Hex string (24+ chars, e.g. MongoDB ObjectId)
        if (seg.matches("[0-9a-fA-F]{24,}")) return true;
        // Base64-like encoded ID (20+ chars, URL-safe)
        if (seg.matches("[A-Za-z0-9_-]{20,}")) return true;
        return false;
    }

    /** Enhanced: try to extract resource ID from JSON request body. */
    private static String extractIdFromBody(String body) {
        if (body == null) return null;
        // Common ID field names in request bodies
        String[] idFields = {"id", "Id", "ID", "resourceId", "resource_id",
                "itemId", "item_id", "objectId", "object_id",
                "orderId", "order_id", "userId", "user_id"};
        for (String field : idFields) {
            Matcher m = Pattern.compile("\"" + Pattern.quote(field) + "\"\\s*:\\s*\"?([^\",}\\s]+)\"?").matcher(body);
            if (m.find()) {
                String val = m.group(1);
                if (isResourceId(val)) return val;
            }
        }
        return null;
    }

    private static String extractFormValue(String kv, String param) {
        for (String pair : kv.split("&")) {
            int eq = pair.indexOf('=');
            if (eq > 0 && pair.substring(0, eq).equalsIgnoreCase(param)) {
                return urlDecode(pair.substring(eq + 1));
            }
        }
        return null;
    }

    /** Find "param":"value" (JSON) or param=value (form) anywhere in the text. */
    private static String extractJsonOrFormValue(String s, String param) {
        if (s == null || s.isEmpty()) return null;
        Matcher m = Pattern.compile("\"" + Pattern.quote(param) + "\"\\s*:\\s*\"([^\"]+)\"").matcher(s);
        if (m.find()) return m.group(1);
        m = Pattern.compile("(?:^|[?&])" + Pattern.quote(param) + "=([^&\"\\s]+)").matcher(s);
        if (m.find()) return m.group(1);
        return null;
    }

    private static String extractField(String body, String field) {
        if (body == null || field == null) return null;
        Matcher m = Pattern.compile("\"" + Pattern.quote(field) + "\"\\s*:\\s*\"([^\"]+)\"").matcher(body);
        return m.find() ? m.group(1) : null;
    }

    // ---- similarity ----

    private static double similarity(String a, String b) {
        if (a == null && b == null) return 1.0;
        if (a == null || b == null) return 0.0;
        if (a.equals(b)) return 1.0;
        Set<String> sa = shingles(a, 4);
        Set<String> sb = shingles(b, 4);
        if (sa.isEmpty() && sb.isEmpty()) return 1.0;
        long inter = 0;
        for (String s : sa) if (sb.contains(s)) inter++;
        long union = sa.size() + sb.size() - inter;
        return union == 0 ? 0 : (double) inter / union;
    }

    private static Set<String> shingles(String s, int k) {
        Set<String> out = new HashSet<>();
        if (s == null || s.length() < k) {
            if (s != null && !s.isEmpty()) out.add(s);
            return out;
        }
        for (int i = 0; i + k <= s.length(); i++) out.add(s.substring(i, i + k));
        return out;
    }

    // ---- helpers ----

    private static String urlDecode(String s) {
        if (s == null) return null;
        try {
            return java.net.URLDecoder.decode(s, java.nio.charset.StandardCharsets.UTF_8);
        } catch (Exception e) {
            return s;
        }
    }

    private static String snippet(String s) {
        if (s == null) return "";
        return s.length() > 300 ? s.substring(0, 300) + "..." : s;
    }

    private static String pct(double d) {
        return String.format("%.0f%%", d * 100);
    }

    private static String err(String msg) {
        JsonObject o = new JsonObject();
        o.addProperty("error", msg);
        return o.toString();
    }

    /** One captured request+response for a resource from one session. */
    private record Captured(String sessionFp, HttpRequest req, String body, int statusCode) {}
}
