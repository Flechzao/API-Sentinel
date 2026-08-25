package com.flechazo.apisentinel.ai.agent.tool;

import com.flechazo.apisentinel.ui.CodeExecutionConfirmDialog;
import com.flechazo.apisentinel.util.SandboxProcessRunner;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

import java.awt.Frame;

public class RunSandboxedCodeTool implements AgentTool {

    private static final int TIMEOUT_SECONDS = 15;
    private static final int MAX_OUTPUT_CHARS = 20_000;

    private final ToolContext ctx;

    public RunSandboxedCodeTool(ToolContext ctx) {
        this.ctx = ctx;
    }

    @Override
    public String name() { return "run_sandboxed_code"; }

    @Override
    public String description() {
        return "在本机跑一段 Python/Node 脚本做纯计算（复现算法、编解码、密码学计算），"
             + "验证一个不依赖真实目标响应就能判断的假设（比如某个签名算法是否可逆、某个哈希"
             + "能不能被已知规则暴力枚举、某段自定义编码怎么解）。"
             + "重要边界：这个沙箱只做到独立子进程+独立临时目录+超时强杀+输出截断，"
             + "**不保证隔离网络访问、不保证隔离对真机真实文件系统的绝对路径访问**——"
             + "不是一个技术上无法绕过的沙箱，真正的安全边界是执行前的人工确认（除非用户在"
             + "设置里主动开启了自动批准）。因此：不要用它来跟目标交互（那是 send_request 的职责），"
             + "只用来做脚本能独立跑出结果的纯计算验证；purpose 字段要如实说明用途，会展示给用户看。";
    }

    @Override
    public JsonObject inputSchema() {
        JsonObject schema = new JsonObject();
        schema.addProperty("type", "object");
        JsonObject props = new JsonObject();

        JsonObject codeProp = new JsonObject();
        codeProp.addProperty("type", "string");
        codeProp.addProperty("description", "要执行的完整脚本内容。");
        props.add("code", codeProp);

        JsonObject purposeProp = new JsonObject();
        purposeProp.addProperty("type", "string");
        purposeProp.addProperty("description", "简短说明这段代码要验证什么（会展示在确认弹窗里给用户看）。");
        props.add("purpose", purposeProp);

        JsonObject interpreterProp = new JsonObject();
        interpreterProp.addProperty("type", "string");
        interpreterProp.addProperty("description", "指定解释器，缺省自动探测本机可用的 python3/python/node。");
        JsonArray interpreterEnum = new JsonArray();
        interpreterEnum.add("python");
        interpreterEnum.add("python3");
        interpreterEnum.add("node");
        interpreterProp.add("enum", interpreterEnum);
        props.add("interpreter", interpreterProp);

        schema.add("properties", props);
        JsonArray required = new JsonArray();
        required.add("code");
        required.add("purpose");
        schema.add("required", required);
        return schema;
    }

    @Override
    public String execute(String argumentsJson) {
        String code;
        String purpose;
        String requestedInterpreter = null;
        try {
            var parsed = com.google.gson.JsonParser.parseString(argumentsJson).getAsJsonObject();
            code = parsed.has("code") ? parsed.get("code").getAsString() : "";
            purpose = parsed.has("purpose") ? parsed.get("purpose").getAsString() : "";
            if (parsed.has("interpreter") && !parsed.get("interpreter").isJsonNull()) {
                requestedInterpreter = parsed.get("interpreter").getAsString();
            }
        } catch (Exception e) {
            return "{\"success\": false, \"error\": \"invalid arguments: " + escapeJson(e.getMessage()) + "\"}";
        }
        if (code.isBlank()) {
            return "{\"success\": false, \"error\": \"code must not be empty\"}";
        }

        SandboxProcessRunner.Interpreter interpreter = SandboxProcessRunner.detectInterpreter(requestedInterpreter);
        if (interpreter == null) {
            return "{\"success\": false, \"error\": \"本机未找到可用的解释器"
                    + (requestedInterpreter != null ? " (" + escapeJson(requestedInterpreter) + ")" : " (python3/python/node)")
                    + "，无法执行\"}";
        }

        boolean autoApprove = ctx.pipelineConfig() != null && ctx.pipelineConfig().codeExecutionAutoApprove();
        if (!autoApprove) {
            Boolean approved = null;
            UserInteractionBridge bridge = ctx.userInteractionBridge();
            if (bridge != null) {
                // Inline chat card — the primary path. It renders the code in the
                // conversation flow (no separate modal window); a timeout counts
                // as reject, same safe default as the dialog below.
                approved = bridge.askConfirmation("Agent 请求执行代码", purpose, code,
                        "允许执行", "拒绝", 300);
            }
            if (approved == null && bridge == null) {
                // Fallback: no bridge attached (no UI) — the old blocking dialog.
                Frame owner = null;
                burp.api.montoya.MontoyaApi mapi = null;
                try {
                    if (ctx.montoyaApi() != null) {
                        mapi = ctx.montoyaApi();
                        owner = mapi.userInterface().swingUtils().suiteFrame();
                    }
                } catch (Exception ignored) {}
                approved = CodeExecutionConfirmDialog.confirmBlocking(
                        owner, mapi, purpose, interpreter.name(), code);
            }
            if (!Boolean.TRUE.equals(approved)) {
                return "{\"success\": false, \"error\": \"用户拒绝执行（或确认超时）\"}";
            }
        }

        SandboxProcessRunner.SandboxResult result =
                SandboxProcessRunner.run(interpreter, code, TIMEOUT_SECONDS, MAX_OUTPUT_CHARS);

        JsonObject out = new JsonObject();
        if (result.error() != null) {
            out.addProperty("success", false);
            out.addProperty("error", result.error());
            return out.toString();
        }
        out.addProperty("success", result.success());
        out.addProperty("exit_code", result.exitCode());
        out.addProperty("timed_out", result.timedOut());
        out.addProperty("truncated", result.truncated());
        out.addProperty("stdout", result.stdout());
        out.addProperty("stderr", result.stderr());
        return out.toString();
    }

    private static String escapeJson(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n");
    }
}
