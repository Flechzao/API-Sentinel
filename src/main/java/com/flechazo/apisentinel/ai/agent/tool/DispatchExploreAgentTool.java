package com.flechazo.apisentinel.ai.agent.tool;

import com.flechazo.apisentinel.ai.agent.ExplorationSubAgent;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

public class DispatchExploreAgentTool implements AgentTool {

    private final ToolContext ctx;

    public DispatchExploreAgentTool(ToolContext ctx) {
        this.ctx = ctx;
    }

    @Override
    public String name() { return "dispatch_explore_agent"; }

    @Override
    public String description() {
        return "把一个范围较宽的探索性问题委派给一个隔离的只读子 Agent（例如"
             + "\"整个仓库哪些地方校验 JWT\"、\"这个功能从 Controller 到数据库落地的完整调用链\"），"
             + "只拿回一段综合结论，不必自己占用上下文逐个调用 read_file/grep_repo 再手动整理。"
             + "子 Agent 只有只读工具（read_file/grep_repo/search_source_code/audit_codebase/"
             + "find_definition/find_callers/search_traffic/fingerprint_components/"
             + "heuristic_scan/list_sessions），不发 HTTP 请求、不生成 payload，因此它的结论只是"
             + "情报——你仍需自己用 send_request 等工具做实测验证才能在最终报告里定级。"
             + "适合在已经调用过几轮 read_file/grep_repo 仍没查全、想一次性铺开搜索时使用。免费，"
             + "不消耗你自己的上下文。";
    }

    @Override
    public JsonObject inputSchema() {
        JsonObject schema = new JsonObject();
        schema.addProperty("type", "object");
        JsonObject props = new JsonObject();

        JsonObject taskProp = new JsonObject();
        taskProp.addProperty("type", "string");
        taskProp.addProperty("description", "要调查的具体问题，描述越具体子 Agent 查得越准"
                + "（例如\"在整个代码仓库中找出所有反序列化不受信任数据的位置，并说明每处数据来源\"）。");
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

        // Fresh ToolContext — never reuse the parent's: ToolSessionState is
        // mutable and tracks cross-tool gates (heuristic_scan called?, verified
        // payload count, ...) that must stay scoped to the parent's own tool
        // calls, not get polluted by the sub-agent's read-only exploration.
        ToolContext subCtx = new ToolContext(ctx.entry(), ctx.provider(), ctx.montoyaApi(),
                ctx.codeIndexService(), ctx.codeRepos(), ctx.pipelineConfig(), ctx.logger(),
                ctx.oobService());
        AgentToolRegistry subRegistry = StandardToolRegistry.buildExploration(subCtx);

        ExplorationSubAgent.Result result = ExplorationSubAgent.run(ctx.provider(), subRegistry, task, ctx.logger());

        JsonObject out = new JsonObject();
        out.addProperty("success", result.success());
        if (result.success()) {
            out.addProperty("summary", result.summary());
        } else {
            out.addProperty("error", result.error());
        }
        out.addProperty("iterations_used", result.iterationsUsed());
        JsonArray toolsArr = new JsonArray();
        if (result.toolsCalled() != null) result.toolsCalled().forEach(toolsArr::add);
        out.add("tools_called", toolsArr);
        return out.toString();
    }

    private static String escapeJson(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n");
    }
}
