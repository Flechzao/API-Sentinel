package com.flechazo.apisentinel.ai.agent.tool;

import com.flechazo.apisentinel.detection.HeuristicDetector;
import com.flechazo.apisentinel.model.ApiEntry;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

import java.util.List;

public class HeuristicScanTool implements AgentTool {

    private final ToolContext ctx;

    public HeuristicScanTool(ToolContext ctx) {
        this.ctx = ctx;
    }

    @Override
    public String name() { return "heuristic_scan"; }

    @Override
    public boolean isReadOnly() { return true; }

    @Override
    public String description() {
        return "Run fast local heuristic detection on the HTTP traffic. Checks for SQL error messages, "
             + "stack traces, server version disclosure, CORS misconfiguration, JWT issues, CSRF, "
             + "request smuggling, and more. Free, instant, regex-based — no AI cost.";
    }

    @Override
    public JsonObject inputSchema() {
        JsonObject schema = new JsonObject();
        schema.addProperty("type", "object");
        schema.add("properties", new JsonObject());
        return schema;
    }

    @Override
    public String execute(String argumentsJson) {
        var entry = ctx.entry();
        HeuristicDetector detector = new HeuristicDetector(ctx.logger());

        String method = entry.getHttpMethod() != null ? entry.getHttpMethod() : "GET";
        String url = entry.getLastUrl() != null ? entry.getLastUrl() : entry.getApiPath();
        String rawReq = entry.getLastRawRequest() != null ? entry.getLastRawRequest() : "";
        String rawResp = entry.getLastRawResponse() != null ? entry.getLastRawResponse() : "";
        int statusCode = entry.getLastStatusCode();

        try {
            var findings = detector.detect(method, url, rawReq, rawResp, statusCode);

            JsonObject result = new JsonObject();
            result.addProperty("findings_count", findings.size());

            JsonArray arr = new JsonArray();
            for (var f : findings) {
                JsonObject fo = new JsonObject();
                fo.addProperty("risk", f.risk());
                fo.addProperty("category", f.category());
                fo.addProperty("title", f.title());
                fo.addProperty("evidence", f.evidence());
                fo.addProperty("remediation", f.remediation());
                arr.add(fo);
            }
            result.add("findings", arr);

            // A 0-finding result is genuinely common and expected (most clean
            // JSON APIs trigger none of the regex signatures — e.g. missing-
            // security-headers only fires on HTML responses, SQL-error only on
            // specific DB-engine error strings, etc.), but a bare
            // {"findings_count":0,"findings":[]} reads to the model like "scan
            // broken / nothing to say". Surface a one-line explanation so the
            // model knows 0 means "checked, nothing matched" rather than "error",
            // AND fold in whatever the passive layer already found (written to
            // entry.note by HttpTrafficHandler's real-time SensitiveInfo /
            // Unauthorized / Heuristic detectors) so this one tool call gives a
            // consolidated "what's been found so far" view instead of just the
            // fresh scan.
            if (findings.isEmpty()) {
                result.addProperty("note",
                        "本地启发式正则检测未命中任何已知签名（正常 JSON 接口通常如此：缺失安全头仅对 HTML "
                      + "响应触发、SQL 报错仅匹配 MySQL/PostgreSQL/SQL Server/SQLite 等特定引擎错误串等）。"
                      + "这不代表该接口安全，仅代表本地的快速正则没有发现明显异常，仍需结合流量/代码做深度分析。");
            }

            if (entry.hasPassiveFindings()) {
                JsonArray pfArr = new JsonArray();
                for (com.flechazo.apisentinel.model.PassiveFinding f : entry.getPassiveFindings()) {
                    JsonObject fo = new JsonObject();
                    fo.addProperty("source", f.source().name());
                    fo.addProperty("risk", f.risk());
                    fo.addProperty("category", f.category());
                    fo.addProperty("title", f.title());
                    fo.addProperty("evidence", f.evidence());
                    pfArr.add(fo);
                }
                result.add("passive_findings", pfArr);
            }

            // Suggest next step based on what was found
            result.addProperty("next_step", buildNextStep(findings, entry));

            return result.toString();
        } catch (Exception e) {
            return "{\"findings_count\": 0, \"error\": \"" + escapeJson(e.getMessage()) + "\"}";
        }
    }

    private static String escapeJson(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n");
    }

    private String buildNextStep(List<com.flechazo.apisentinel.detection.HeuristicDetector.HeuristicFinding> findings,
                                  ApiEntry entry) {
        for (var f : findings) {
            String cat = f.category() != null ? f.category().toLowerCase() : "";
            if (cat.contains("sql") || cat.contains("注入")) {
                return "建议: 发现 SQL 相关线索，如果显错注入失败，调用 verify_boolean_blind 或 verify_timing_blind 验证盲注";
            }
            if (cat.contains("cors") || cat.contains("跨域")) {
                return "建议: 发现 CORS 配置问题，调用 active_probe 做 CORS Origin 变体反射验证";
            }
            if (cat.contains("jwt") || cat.contains("token")) {
                return "建议: 发现 JWT 相关线索，调用 active_probe 做 JWT alg:none 伪造重放";
            }
            if (cat.contains("csrf")) {
                return "建议: 发现 CSRF 风险，检查是否有敏感操作（修改密码/转账）可被 CSRF 利用";
            }
        }
        if (entry.hasPassiveFindings()) {
            return "建议: 被动检测有发现，调用 analyze_traffic 做 AI 深度分析，或直接调用 generate_payloads 生成测试";
        }
        if (findings.isEmpty()) {
            return "建议: 本地正则无发现，调用 search_source_code 查看后端代码，或调用 analyze_traffic 做 AI 深度分析";
        }
        return "建议: 调用 analyze_traffic 做 AI 深度分析，或调用 generate_payloads 生成针对性测试 payload";
    }
}
