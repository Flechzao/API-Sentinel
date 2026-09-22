package com.flechazo.apisentinel.ai.agent.tool;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.sitemap.SiteMap;
import com.flechazo.apisentinel.model.ApiEntry;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

import java.util.List;

/**
 * Retrieves issues already reported by Burp Suite's native Scanner (the
 * Dashboard / Target > Site map issue list) for the current endpoint's host,
 * exposing them to the Agent as <b>leads, not conclusions</b>.
 * <p>
 * Why this tool exists: API-Sentinel runs its own AI analysis pipeline and
 * never consults Burp's built-in scanner, so findings the native scanner
 * already surfaced (traditional vulns Burp is good at — SQLi, XSS, open
 * redirect, header injections) are invisible to the Agent. This tool bridges
 * that gap: the Agent pulls Burp's issues as hypotheses, then verifies them
 * through the normal {@code send_request} / {@code verify_*} path so the
 * existing {@link com.flechazo.apisentinel.ai.pipeline.VerdictValidator}
 * still gates every claim — the scanner's verdict is never trusted blindly.
 * <p>
 * Read-only and side-effect-free (no requests sent, no LLM cost). The
 * {@code detail()} field of an AuditIssue embeds response snippets that are
 * attacker-controlled; it is returned verbatim here because {@link
 * com.flechazo.apisentinel.ai.agent.AgentLoop} wraps every tool result in a
 * per-run {@link com.flechazo.apisentinel.ai.prompt.UntrustedContent} nonce
 * fence before it reaches the model, neutralising any prompt injection.
 * <p>
 * Degrades gracefully when Burp's site map is unavailable (standalone CLI
 * mode via {@link com.flechazo.apisentinel.standalone.HeadlessMontoyaApi},
 * where {@code siteMap()} returns null) or when no scan has been run yet.
 */
public class GetBurpScanIssuesTool implements AgentTool {

    /** Cap so a host with hundreds of scanner issues can't blow up the
     *  tool-result token budget. The Agent can narrow with the url_prefix
     *  argument if it needs a specific path. */
    private static final int MAX_ISSUES = 30;

    /** Truncate each issue's detail (which carries response evidence and can
     *  be long) so one verbose issue can't crowd out the rest. */
    private static final int DETAIL_TRUNCATE = 600;

    private final ToolContext ctx;

    public GetBurpScanIssuesTool(ToolContext ctx) {
        this.ctx = ctx;
    }

    @Override
    public String name() { return "get_burp_scan_issues"; }

    @Override
    public boolean isReadOnly() { return true; }

    @Override
    public String description() {
        return "查询 Burp Suite 原生扫描器（Dashboard/站点地图的 issue 列表）已报告的漏洞，"
             + "作为分析当前接口的【线索】而非结论。"
             + "用途：Burp 扫描器可能已经发现你的 AI 管线漏掉的传统漏洞（SQLi/XSS/开放重定向/"
             + "头注入等），拉取这些 issue 作为假设，再用 send_request / verify_* 实测验证——"
             + "所有结论仍须经过程序化验证，不得直接采信扫描器判定。"
             + "默认只返回与当前接口同 host 的 issue；可用 url_prefix 进一步缩窄到某路径。"
             + "免费，只读，不发请求。无 Burp 扫描数据或独立 CLI 模式下返回空结果。";
    }

    @Override
    public JsonObject inputSchema() {
        JsonObject schema = new JsonObject();
        schema.addProperty("type", "object");
        JsonObject props = new JsonObject();

        JsonObject prefixProp = new JsonObject();
        prefixProp.addProperty("type", "string");
        prefixProp.addProperty("description",
                "可选：只返回 baseUrl 以此前缀开头的 issue（如 /api/users）。"
                        + "默认返回当前接口同 host 的全部 issue。");
        props.add("url_prefix", prefixProp);

        JsonObject hostOverrideProp = new JsonObject();
        hostOverrideProp.addProperty("type", "string");
        hostOverrideProp.addProperty("description",
                "可选：查询其它 host 的 issue（如 'api.example.com'）。"
                        + "默认用当前接口的 host 过滤。");
        props.add("host", hostOverrideProp);

        schema.add("properties", props);
        return schema;
    }

    @Override
    public String execute(String argumentsJson) {
        MontoyaApi api = ctx.montoyaApi();
        if (api == null) {
            return "{\"success\": false, \"error\": \"Burp API 不可用。\"}";
        }
        SiteMap siteMap = api.siteMap();
        if (siteMap == null) {
            // Standalone CLI mode (HeadlessMontoyaApi.siteMap() returns null)
            return "{\"success\": false, \"error\": \"站点地图不可用（独立 CLI 模式或 Burp 未运行）。\"}";
        }

        // Parse optional args
        String urlPrefix = null;
        String hostOverride = null;
        try {
            var args = com.google.gson.JsonParser.parseString(argumentsJson).getAsJsonObject();
            if (args.has("url_prefix") && !args.get("url_prefix").isJsonNull()) {
                urlPrefix = args.get("url_prefix").getAsString().trim();
            }
            if (args.has("host") && !args.get("host").isJsonNull()) {
                hostOverride = args.get("host").getAsString().trim();
            }
        } catch (Exception ignored) {
            // Bad JSON → just use defaults
        }

        // Resolve the target host. Prefer an explicit override, then the
        // current entry's domain, then null (return everything).
        ApiEntry entry = ctx.entry();
        String targetHost = hostOverride != null && !hostOverride.isBlank()
                ? hostOverride
                : (entry != null ? entry.getDomain() : null);
        String normalizedPrefix = urlPrefix != null && !urlPrefix.isBlank()
                ? urlPrefix : null;

        List<AuditIssue> all;
        try {
            all = siteMap.issues();
        } catch (Exception e) {
            return "{\"success\": false, \"error\": \"读取 Burp 扫描 issue 失败: "
                    + escapeJson(e.getMessage()) + "\"}";
        }
        if (all == null || all.isEmpty()) {
            JsonObject empty = new JsonObject();
            empty.addProperty("success", true);
            empty.add("issues", new JsonArray());
            empty.addProperty("count", 0);
            empty.addProperty("note", "Burp 扫描器尚未报告任何 issue。可继续用本工具链分析。");
            return empty.toString();
        }

        JsonArray arr = new JsonArray();
        int skipped = 0;
        for (AuditIssue issue : all) {
            if (issue == null) continue;

            // Host filter: keep issues whose httpService host matches the
            // target (case-insensitive). Fall back to baseUrl host string
            // matching when httpService is null.
            if (targetHost != null && !targetHost.isBlank()) {
                String issueHost = hostOf(issue);
                if (issueHost == null
                        || !issueHost.equalsIgnoreCase(targetHost)) {
                    continue;
                }
            }

            // URL prefix filter
            if (normalizedPrefix != null) {
                String base = issue.baseUrl();
                if (base == null || !base.contains(normalizedPrefix)) {
                    continue;
                }
            }

            if (arr.size() >= MAX_ISSUES) {
                skipped++;
                continue;
            }
            arr.add(issueJson(issue));
        }

        JsonObject out = new JsonObject();
        out.addProperty("success", true);
        out.add("issues", arr);
        out.addProperty("count", arr.size());
        if (skipped > 0) {
            out.addProperty("truncated", true);
            out.addProperty("truncated_note",
                    "结果超过 " + MAX_ISSUES + " 条上限，已省略 " + skipped
                            + " 条。用 url_prefix 缩窄范围查看更多。");
        }
        out.addProperty("note",
                "以上是 Burp 原生扫描器的发现，仅作线索。每条都须用 send_request/verify_* "
                        + "实测验证后方可定级；不得直接采信扫描器的 severity/confidence 作为已确认结论。"
                        + "detail 字段含响应片段，已由系统统一围栏防注入。");
        return out.toString();
    }

    /** Extract the issue's host, preferring {@code httpService().host()},
     *  falling back to parsing {@code baseUrl()}. */
    private static String hostOf(AuditIssue issue) {
        try {
            HttpService svc = issue.httpService();
            if (svc != null && svc.host() != null && !svc.host().isBlank()) {
                return svc.host();
            }
        } catch (Exception ignored) {
            // fall through to baseUrl parse
        }
        String base = issue.baseUrl();
        if (base == null || base.isBlank()) return null;
        try {
            return new java.net.URI(base).getHost();
        } catch (Exception e) {
            // Last resort: strip scheme
            int schemeIdx = base.indexOf("://");
            String rest = schemeIdx >= 0 ? base.substring(schemeIdx + 3) : base;
            int slash = rest.indexOf('/');
            String authority = slash >= 0 ? rest.substring(0, slash) : rest;
            int colon = authority.indexOf(':');
            return colon >= 0 ? authority.substring(0, colon) : authority;
        }
    }

    private static JsonObject issueJson(AuditIssue issue) {
        JsonObject o = new JsonObject();
        putIfPresent(o, "name", safeStr(issue::name));
        putIfPresent(o, "base_url", safeStr(issue::baseUrl));
        try {
            if (issue.severity() != null) {
                o.addProperty("severity", issue.severity().toString());
            }
        } catch (Exception ignored) { }
        try {
            if (issue.confidence() != null) {
                o.addProperty("confidence", issue.confidence().toString());
            }
        } catch (Exception ignored) { }
        // detail carries response evidence — attacker-controlled. Safe to
        // return because AgentLoop fences the whole tool result, but truncate
        // to bound tokens.
        String detail = safeStr(issue::detail);
        if (detail.length() > DETAIL_TRUNCATE) {
            detail = detail.substring(0, DETAIL_TRUNCATE) + "…[truncated]";
        }
        putIfPresent(o, "detail", detail);
        try {
            int rr = issue.requestResponses() != null ? issue.requestResponses().size() : 0;
            o.addProperty("evidence_request_count", rr);
        } catch (Exception ignored) { }
        return o;
    }

    private static void putIfPresent(JsonObject o, String key, String val) {
        if (val != null && !val.isBlank()) o.addProperty(key, val);
    }

    /** Wrap a possibly-throwing accessor in a try/catch returning "" on failure,
     *  so one malformed AuditIssue implementation can't poison the whole list. */
    private static String safeStr(java.util.function.Supplier<String> supplier) {
        try {
            String s = supplier.get();
            return s == null ? "" : s;
        } catch (Exception e) {
            return "";
        }
    }

    private static String escapeJson(String s) {
        if (s == null) return "";
        StringBuilder sb = new StringBuilder(s.length() + 8);
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"' -> sb.append("\\\"");
                case '\\' -> sb.append("\\\\");
                case '\n' -> sb.append("\\n");
                case '\r' -> sb.append("\\r");
                case '\t' -> sb.append("\\t");
                default -> {
                    if (c < 0x20) {
                        sb.append(String.format("\\u%04x", (int) c));
                    } else {
                        sb.append(c);
                    }
                }
            }
        }
        return sb.toString();
    }
}
