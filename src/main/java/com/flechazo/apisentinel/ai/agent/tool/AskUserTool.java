package com.flechazo.apisentinel.ai.agent.tool;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

import java.util.ArrayList;
import java.util.List;

/**
 * ask_user — lets the Agent pause and ask the human operator a question with
 * optional multiple-choice options (Claude-Code style). Use it when the next
 * step genuinely depends on information only the operator has, or when two
 * reasonable paths exist and guessing would burn analysis budget on the wrong
 * one. NOT for anything answerable from code/traffic/tools.
 *
 * When no UI bridge is attached, or the user doesn't respond in time, the
 * tool returns answered:false — the Agent must then proceed autonomously and
 * say so in the final report. A missing answer never aborts the analysis.
 */
public class AskUserTool implements AgentTool {

    /** How long the card stays actionable before auto-skipping. Generous on
     *  purpose: the operator may be watching a different tab. */
    static final long TIMEOUT_SECONDS = 300;
    private static final int MAX_OPTIONS = 6;

    private final ToolContext ctx;

    public AskUserTool(ToolContext ctx) {
        this.ctx = ctx;
    }

    @Override
    public String name() { return "ask_user"; }

    @Override
    public String description() {
        return "向用户（安全测试人员）提一个问题，可选地给出 2-6 个候选项让用户点选。"
             + "适用场景：只有用户才知道的信息（比如某个疑似密钥是不是公开的、测试账号归属）、"
             + "或下一步方向存在实质分歧且猜错会浪费大量验证预算时请求用户定夺。"
             + "不适用：任何能通过读代码/查流量/其他工具自己回答的问题。"
             + "用户未响应（超时约 5 分钟）或无交互界面时返回 answered=false，"
             + "此时你必须基于现有证据自主决策并在报告中注明，不要反复重问同一问题。";
    }

    @Override
    public JsonObject inputSchema() {
        JsonObject schema = new JsonObject();
        schema.addProperty("type", "object");
        JsonObject props = new JsonObject();

        JsonObject questionProp = new JsonObject();
        questionProp.addProperty("type", "string");
        questionProp.addProperty("description", "要问的具体问题，一句话说清背景和你要的答案。");
        props.add("question", questionProp);

        JsonObject contextProp = new JsonObject();
        contextProp.addProperty("type", "string");
        contextProp.addProperty("description", "简短交代你为什么问、你已经排除了什么（会展示给用户看）。");
        props.add("context", contextProp);

        JsonObject optionsProp = new JsonObject();
        optionsProp.addProperty("type", "array");
        optionsProp.addProperty("description", "候选答案（2-6 个，每个都是简短选项文本）。省略则为开放式提问。");
        JsonObject itemProp = new JsonObject();
        itemProp.addProperty("type", "string");
        optionsProp.add("items", itemProp);
        props.add("options", optionsProp);

        schema.add("properties", props);
        JsonArray required = new JsonArray();
        required.add("question");
        schema.add("required", required);
        return schema;
    }

    @Override
    public String execute(String argumentsJson) {
        String question;
        String context = "";
        List<String> options = new ArrayList<>();
        try {
            var parsed = com.google.gson.JsonParser.parseString(argumentsJson).getAsJsonObject();
            question = parsed.has("question") ? parsed.get("question").getAsString() : "";
            if (parsed.has("context") && !parsed.get("context").isJsonNull()) {
                context = parsed.get("context").getAsString();
            }
            if (parsed.has("options") && parsed.get("options").isJsonArray()) {
                for (var el : parsed.getAsJsonArray("options")) {
                    if (el.isJsonPrimitive() && !el.getAsString().isBlank()) {
                        options.add(el.getAsString());
                    }
                }
            }
        } catch (Exception e) {
            return "{\"answered\": false, \"reason\": \"invalid arguments: "
                    + escape(e.getMessage()) + "\"}";
        }
        if (question == null || question.isBlank()) {
            return "{\"answered\": false, \"reason\": \"question must not be empty\"}";
        }
        if (options.size() > MAX_OPTIONS) {
            options = new ArrayList<>(options.subList(0, MAX_OPTIONS));
        }

        UserInteractionBridge bridge = ctx.userInteractionBridge();
        if (bridge == null) {
            // No UI attached (headless/test/registry misuse) — the analysis
            // must go on; the agent learns to decide on its own.
            return "{\"answered\": false, \"reason\": \"当前无交互界面，用户无法作答——请基于现有证据自主决策\"}";
        }

        Integer choice = bridge.askChoice(question, context, options, TIMEOUT_SECONDS);

        JsonObject out = new JsonObject();
        if (choice == null) {
            out.addProperty("answered", false);
            out.addProperty("reason", "用户未响应（超时或跳过）——请基于现有证据自主决策，并在报告中注明该问题未获用户确认");
        } else if (choice == -2) {
            // User typed a custom free-text answer
            String customText = bridge.getLastCustomAnswer();
            out.addProperty("answered", true);
            out.addProperty("choice", customText != null ? customText : "(empty)");
            out.addProperty("index", -2);
            out.addProperty("custom", true);
        } else {
            out.addProperty("answered", true);
            out.addProperty("choice", options.get(choice));
            out.addProperty("index", choice);
        }
        return out.toString();
    }

    private static String escape(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n");
    }
}
