package com.flechazo.apisentinel.ai.agent.tool;

import com.flechazo.apisentinel.ai.agent.ChainHunterSubAgent;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

/**
 * Delegates a cluster hunt to ChainHunterSubAgent after the main agent
 * confirms/suspects bug A. The sub-agent maps sibling endpoints and replays
 * A's attack pattern against each with REAL requests. The parent's
 * SendRequestTool instance is shared into the sub-registry, so every request
 * the sub-agent sends lands in the parent's PayloadResults — VerdictValidator
 * and the Repeater view see it exactly like requests the parent sent itself
 * (same pattern as ActiveProbeTool reusing the parent's sendTool).
 */
public class ChainHunterTool implements AgentTool {

    private final ToolContext ctx;
    private final SendRequestTool sharedSendTool;

    public ChainHunterTool(ToolContext ctx, SendRequestTool sharedSendTool) {
        this.ctx = ctx;
        this.sharedSendTool = sharedSendTool;
    }

    @Override
    public String name() { return "chain_hunter"; }

    @Override
    public String description() {
        return "在确认/疑似漏洞 A 后，委派一个集群狩猎子代理把 A 的攻击模式系统性扩散到"
             + "兄弟端点（同 Controller/同资源前缀，自动发现）并尝试 A→B 串链。子代理会发送"
             + "真实 HTTP 请求实测每个兄弟端点（写方法优先），并返回覆盖清单+链式发现报告。"
             + "它发出的每个请求都会进入本会话的验证记录（与你自己 send_request 等价，"
             + "最终定级仍由你完成）。消耗 LLM 轮次但请求免费。适合：确认 IDOR 后测同 Controller "
             + "的 PUT/DELETE、确认注入后测兄弟参数、单端点验证完毕想铺开到资源组时使用。"
             + "task 参数要写清楚 A 是什么（类型+证据+成功 payload）。";
    }

    @Override
    public JsonObject inputSchema() {
        JsonObject schema = new JsonObject();
        schema.addProperty("type", "object");
        JsonObject props = new JsonObject();

        JsonObject taskProp = new JsonObject();
        taskProp.addProperty("type", "string");
        taskProp.addProperty("description", "已确认的漏洞 A 描述，供子代理复制攻击模式。格式建议："
                + "漏洞类型 + 触发方式 + 成功 payload/请求特征 + 证据摘要"
                + "（例如\"IDOR 读越权：GET /api/users/{id} 替换 id 为他人 ID 返回他人 PII（200），"
                + "payload 为路径 ID 替换，身份证据是会话 A 换 victim ID 拿到会话 B 数据\"）。");
        props.add("task", taskProp);

        schema.add("properties", props);
        JsonArray required = new JsonArray();
        required.add("task");
        schema.add("required", required);
        return schema;
    }

    @Override
    public String execute(String argumentsJson) {
        String task;
        try {
            var parsed = com.google.gson.JsonParser.parseString(argumentsJson).getAsJsonObject();
            task = parsed.has("task") ? parsed.get("task").getAsString() : "";
        } catch (Exception e) {
            return "{\"success\": false, \"error\": \"invalid arguments: " + escapeJson(e.getMessage()) + "\"}";
        }
        if (task.isBlank()) {
            return "{\"success\": false, \"error\": \"task must not be empty\"}";
        }

        int requestsBefore = sharedSendTool != null ? sharedSendTool.getPayloadResults().size() : 0;

        // Fresh ToolContext (same isolation rationale as DispatchExploreAgentTool):
        // session-state gates stay scoped to the parent's own calls. The one
        // deliberate exception is the SHARED SendRequestTool instance registered
        // below — sub-agent requests must land in the parent's PayloadResults.
        ToolContext subCtx = new ToolContext(ctx.entry(), ctx.provider(), ctx.montoyaApi(),
                ctx.codeIndexService(), ctx.codeRepos(), ctx.pipelineConfig(), ctx.logger(),
                ctx.oobService());
        AgentToolRegistry subRegistry = StandardToolRegistry.buildChainHunter(subCtx, sharedSendTool);

        ChainHunterSubAgent.Result result = ChainHunterSubAgent.run(ctx.provider(), subRegistry, task, ctx.logger());

        int requestsSent = (sharedSendTool != null ? sharedSendTool.getPayloadResults().size() : 0) - requestsBefore;

        JsonObject out = new JsonObject();
        out.addProperty("success", result.success());
        if (result.success()) {
            out.addProperty("report", result.summary());
        } else {
            out.addProperty("error", result.error());
        }
        out.addProperty("iterations_used", result.iterationsUsed());
        out.addProperty("requests_sent", requestsSent);
        JsonArray toolsArr = new JsonArray();
        if (result.toolsCalled() != null) result.toolsCalled().forEach(toolsArr::add);
        out.add("tools_called", toolsArr);
        if (result.success()) {
            out.addProperty("note", "子代理发出的 " + requestsSent + " 个请求已计入本会话验证记录。"
                    + "报告中的发现按集群狩猎六步法产出：可信但需你结合身份审计与异常证据综合定级；"
                    + "越权类发现要补 identity_proof（哪个会话/是否测匿名/如何证明是他人数据）。");
        }
        return out.toString();
    }

    private static String escapeJson(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n");
    }
}
