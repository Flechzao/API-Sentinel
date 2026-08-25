package com.flechazo.apisentinel.ai.agent.tool;

import com.flechazo.apisentinel.ai.pipeline.ConfirmedVuln;
import com.flechazo.apisentinel.ai.pipeline.FinalVerdict;
import com.flechazo.apisentinel.ai.pipeline.SuspectedVuln;
import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

import java.util.ArrayList;
import java.util.List;

public class SubmitReportTool implements AgentTool {

    private static final Gson GSON = new Gson();
    private FinalVerdict verdict;

    public FinalVerdict getVerdict() { return verdict; }

    @Override
    public String preExecute(String argumentsJson, ToolContext ctx) {
        var state = ctx.sessionState();

        // Gate 1: heuristic_scan is mandatory (free, instant)
        if (!state.hasCalled("heuristic_scan")) {
            return "{\"error\": \"Report rejected — call heuristic_scan first "
                    + "(it's free and instant) before submitting.\"}";
        }

        // Gate 1b: when code repos are configured, the global white-box audit
        // (audit_codebase) is mandatory — a repo usually has many sinks beyond the
        // one chain already found for the current endpoint. Free, sends no requests.
        if (ctx.codeRepos() != null && !ctx.codeRepos().isEmpty()
                && !state.hasCalled("audit_codebase")) {
            return "{\"error\": \"Report rejected — code repos are configured but you never "
                    + "called audit_codebase. Run the global white-box audit first (it lists every "
                    + "dangerous sink in the repo, free and sends no requests), trace the high-risk "
                    + "ones back to their source, then resubmit. Do not stop at the single chain you "
                    + "already found for the current endpoint.\"}";
        }

        // Gate 2: if payloads were generated, they must be verified
        int generated = state.generatedPayloadCount();
        int verified = state.verifiedPayloadCount();
        int required = Math.min(generated, 5); // cap at 5
        if (generated > 0 && verified < required) {
            return String.format("{\"error\": \"Report rejected — you generated %d test "
                    + "payload(s) via generate_payloads but only verified %d via "
                    + "send_request. Findings must be grounded in real request/response "
                    + "evidence. Call send_request on at least %d of them (prioritize "
                    + "the most promising) before submitting.\"}",
                    generated, verified, required);
        }

        // Gate 3: coverage check — ensure key dimensions are addressed
        StringBuilder missing = new StringBuilder();
        boolean hasInjection = state.hasCalled("send_request") || state.hasCalled("analyze_traffic");
        boolean hasAuth = state.hasCalled("test_auth_bypass");
        boolean hasConfig = state.hasCalled("heuristic_scan"); // covers CORS/JWT/headers

        if (!hasInjection) missing.append("- 注入类检查（至少需 analyze_traffic 或 send_request）\n");
        if (!hasAuth) missing.append("- 鉴权类检查（建议调用 test_auth_bypass）\n");
        if (!hasConfig) missing.append("- 配置类检查（至少需 heuristic_scan）\n");

        if (!missing.isEmpty()) {
            ctx.logger().info("[submit_report] 覆盖率提醒: 以下维度未覆盖:\n%s", missing.toString());
            // This is a soft warning — the report is still accepted but the
            // model is reminded. The postExecute verdict validation will catch
            // any actual vulnerability gaps.
        }

        // Gate 4: every finding needs a real-request verification record. If the
        // verdict reports any confirmed/suspected vuln but no request-sending tool
        // was ever called, the findings are pure code-reading with zero request
        // evidence — reject and force the agent to construct & send real requests
        // (even for code-found findings; abnormal/blocked responses still count).
        int findingCount = countFindings(argumentsJson);
        if (findingCount > 0 && !sentAnyRequest(state)) {
            return String.format("{\"error\": \"Report rejected — you reported %d finding(s) "
                    + "but never sent any real request (send_request / verify_* / active_probe / "
                    + "test_auth_bypass). Every finding needs a real-request verification record. "
                    + "Construct and send a representative request for each finding (extract a valid "
                    + "session/CSRF token from proxy history if the endpoint needs auth), and record "
                    + "the response even if it errors/is blocked. Only a finding that genuinely cannot "
                    + "be triggered by a single request (e.g. second-order/stored injection) may rely "
                    + "on the code data-flow chain, and you must still send at least one request to the "
                    + "inject endpoint.\"}",
                    findingCount);
        }

        return null; // allow
    }

    /** Tools that actually send HTTP requests to the target. */
    private static final List<String> REQUEST_TOOLS = List.of(
            "send_request", "verify_boolean_blind", "verify_timing_blind",
            "verify_xss_reflection", "verify_ssti", "verify_path_traversal",
            "verify_xxe", "active_probe", "verify_business_logic",
            "waf_bypass_retry", "test_auth_bypass");

    private boolean sentAnyRequest(com.flechazo.apisentinel.ai.agent.tool.ToolContext.ToolSessionState state) {
        for (String t : REQUEST_TOOLS) {
            if (state.hasCalled(t)) return true;
        }
        return false;
    }

    /** Count confirmed + suspected vulns in the submitted verdict JSON. */
    private int countFindings(String argumentsJson) {
        try {
            JsonObject obj = com.google.gson.JsonParser.parseString(argumentsJson).getAsJsonObject();
            int n = 0;
            if (obj.has("confirmed_vulns") && obj.get("confirmed_vulns").isJsonArray()) {
                n += obj.getAsJsonArray("confirmed_vulns").size();
            }
            if (obj.has("suspected_vulns") && obj.get("suspected_vulns").isJsonArray()) {
                n += obj.getAsJsonArray("suspected_vulns").size();
            }
            return n;
        } catch (Exception e) {
            return 0;
        }
    }

    @Override
    public void postExecute(String argumentsJson, String result, ToolContext ctx) {
        // The verdict will be cross-validated by VerdictValidator in
        // AgentLoop.buildResult() — no post-processing needed here.
    }

    @Override
    public String name() { return "submit_report"; }

    @Override
    public String description() {
        return "提交最终安全分析报告。当你已收集到足够证据并准备好最终评估时调用此工具。调用后分析会话结束。"
             + "提交前自查：confirmed/suspected 中不得包含纯加固类发现（缺安全头/Cookie标志、CORS通配符无凭证外带、"
             + "仅DNS回连的SSRF、只有报错回显无数据读出的SQLi、版本/banner泄露、内网IP出现、Self-XSS、登出CSRF/"
             + "速率限制缺失、GraphQL introspection本身等）——这些只能放进 recommendations。程序层会对你的结论做"
             + "二次校验，命中黑名单且无链式证据的发现会被自动降级并在 summary 注明。";
    }

    @Override
    public JsonObject inputSchema() {
        JsonObject schema = new JsonObject();
        schema.addProperty("type", "object");
        JsonObject props = new JsonObject();

        JsonObject riskProp = new JsonObject();
        riskProp.addProperty("type", "string");
        riskProp.addProperty("description", "总体风险等级");
        var riskEnum = new JsonArray();
        riskEnum.add("HIGH"); riskEnum.add("MEDIUM"); riskEnum.add("LOW"); riskEnum.add("SAFE");
        riskProp.add("enum", riskEnum);
        props.add("overall_risk", riskProp);

        JsonObject confirmedProp = new JsonObject();
        confirmedProp.addProperty("type", "array");
        confirmedProp.addProperty("description", "已确认的漏洞列表（有明确证据）");
        JsonObject confirmedItem = new JsonObject();
        confirmedItem.addProperty("type", "object");
        JsonObject ciProps = new JsonObject();
        addStringProp(ciProps, "type", "漏洞类型（如 SQL注入、XSS、越权访问等）");
        addStringProp(ciProps, "title", "简短标题（中文）");
        addStringProp(ciProps, "evidence", "证明漏洞存在的证据（中文）");
        addStringProp(ciProps, "payload_used", "触发漏洞的Payload");
        addStringProp(ciProps, "response", "相关响应片段");
        addStringProp(ciProps, "verify_command", "复现命令或步骤");
        addStringProp(ciProps, "identity_proof", "越权类（IDOR/未授权/越权访问）必填：用的哪个会话上下文验证？"
                + "是否测过匿名访问（去掉认证头）及结果？如何确认返回数据属于他人账号而非自己？非越权类留空");
        addStringProp(ciProps, "cvss", "可选 CVSS 评分与向量，如 8.8 (AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)");
        confirmedItem.add("properties", ciProps);
        confirmedProp.add("items", confirmedItem);
        props.add("confirmed_vulns", confirmedProp);

        JsonObject suspectedProp = new JsonObject();
        suspectedProp.addProperty("type", "array");
        suspectedProp.addProperty("description", "疑似但未确认的漏洞列表");
        JsonObject suspectedItem = new JsonObject();
        suspectedItem.addProperty("type", "object");
        JsonObject siProps = new JsonObject();
        addStringProp(siProps, "type", "漏洞类型");
        addStringProp(siProps, "title", "简短标题（中文）");
        addStringProp(siProps, "reason", "疑似原因（中文）");
        addStringProp(siProps, "confidence", "置信度: HIGH（高度疑似，有部分证据）, MEDIUM（中度疑似）, LOW（低度疑似，仅理论风险）");
        addStringProp(siProps, "verify_command", "验证步骤");
        addStringProp(siProps, "escalation_path", "可选——该弱发现加上什么链能变成真漏洞（如'开放重定向→接OAuth redirect_uri→窃取授权码'）。有链可走才填，无链留空");
        addStringProp(siProps, "payload_used", "用于验证该发现而实际发出的 payload/请求体片段（与你调用 send_request 时发送的内容一致）。"
                + "有发送过验证请求就务必填上，便于把发现关联到可重放的请求；确属无法用单请求触发的二阶漏洞可留空并注明原因");
        suspectedItem.add("properties", siProps);
        suspectedProp.add("items", suspectedItem);
        props.add("suspected_vulns", suspectedProp);

        addStringProp(props, "summary", "分析总结摘要（中文）");
        addStringProp(props, "recommendations", "安全修复建议（中文）");

        schema.add("properties", props);

        var required = new JsonArray();
        required.add("overall_risk");
        required.add("summary");
        schema.add("required", required);
        return schema;
    }

    @Override
    public String execute(String argumentsJson) {
        try {
            JsonObject args = GSON.fromJson(argumentsJson, JsonObject.class);

            String overallRisk = args.has("overall_risk") ? args.get("overall_risk").getAsString() : "LOW";
            String summary = args.has("summary") ? args.get("summary").getAsString() : "";
            String recommendations = args.has("recommendations") ? args.get("recommendations").getAsString() : "";

            List<ConfirmedVuln> confirmed = new ArrayList<>();
            if (args.has("confirmed_vulns") && args.get("confirmed_vulns").isJsonArray()) {
                for (JsonElement el : args.getAsJsonArray("confirmed_vulns")) {
                    JsonObject v = el.getAsJsonObject();
                    confirmed.add(new ConfirmedVuln(
                            getStr(v, "type"), getStr(v, "title"),
                            getStr(v, "evidence"), getStr(v, "payload_used"),
                            getStr(v, "response"), getStr(v, "verify_command"),
                            getStr(v, "identity_proof"), getStr(v, "cvss")));
                }
            }

            List<SuspectedVuln> suspected = new ArrayList<>();
            if (args.has("suspected_vulns") && args.get("suspected_vulns").isJsonArray()) {
                for (JsonElement el : args.getAsJsonArray("suspected_vulns")) {
                    JsonObject v = el.getAsJsonObject();
                    String conf = getStr(v, "confidence");
                    suspected.add(new SuspectedVuln(
                            getStr(v, "type"), getStr(v, "title"),
                            getStr(v, "reason"), getStr(v, "verify_command"),
                            conf.isEmpty() ? "MEDIUM" : conf,
                            getStr(v, "escalation_path"),
                            getStr(v, "payload_used")));
                }
            }

            verdict = new FinalVerdict(overallRisk, confirmed, suspected, summary, recommendations, 0);
            return "{\"status\": \"Report submitted successfully.\"}";
        } catch (Exception e) {
            return "{\"error\": \"Failed to parse report: " + escapeJson(e.getMessage()) + "\"}";
        }
    }

    private static String getStr(JsonObject o, String key) {
        return o.has(key) && !o.get(key).isJsonNull() ? o.get(key).getAsString() : "";
    }

    private static void addStringProp(JsonObject props, String name, String desc) {
        JsonObject p = new JsonObject();
        p.addProperty("type", "string");
        p.addProperty("description", desc);
        props.add(name, p);
    }

    private static String escapeJson(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n");
    }
}
