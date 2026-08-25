package com.flechazo.apisentinel.ai.agent.tool;

import com.flechazo.apisentinel.codeindex.PathSandbox;
import com.flechazo.apisentinel.codeindex.TaintTracer;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

import java.nio.file.Path;

public class TraceTaintSourceTool implements AgentTool {

    private final ToolContext ctx;

    public TraceTaintSourceTool(ToolContext ctx) {
        this.ctx = ctx;
    }

    @Override
    public String name() { return "trace_taint_source"; }

    @Override
    public String description() {
        return "对一个危险 sink（通常来自 audit_codebase 的结果）做自动化的后向污点回溯：从 sink 所在"
             + "行的变量名开始，沿赋值链向上找，遇到函数参数就跳到调用处继续追，直到找到请求参数/请求体等"
             + "污染源，或者追不下去为止。**这是 regex 启发式回溯，不是真正的数据流分析**——遇到别名赋值、"
             + "字段访问、字符串拼接、多值合并等情况会提前停在 DEAD_END，链路里每一跳都建议用 read_file 核实，"
             + "不要把它的结论直接当作确凿证据。免费，不发请求。";
    }

    @Override
    public JsonObject inputSchema() {
        JsonObject schema = new JsonObject();
        schema.addProperty("type", "object");
        JsonObject props = new JsonObject();

        JsonObject fileProp = new JsonObject();
        fileProp.addProperty("type", "string");
        fileProp.addProperty("description", "sink 所在文件路径（与 audit_codebase/grep_repo 返回的一致，绝对路径或仓库内相对路径均可）。");
        props.add("file", fileProp);

        JsonObject lineProp = new JsonObject();
        lineProp.addProperty("type", "integer");
        lineProp.addProperty("description", "sink 所在行号（1-indexed）。");
        props.add("line", lineProp);

        JsonObject varProp = new JsonObject();
        varProp.addProperty("type", "string");
        varProp.addProperty("description", "sink 代码里被拼接/传入的、你怀疑被污染的变量名（从 sink 代码片段里自己提取）。");
        props.add("variable_name", varProp);

        schema.add("properties", props);
        JsonArray required = new JsonArray();
        required.add("file");
        required.add("line");
        required.add("variable_name");
        schema.add("required", required);
        return schema;
    }

    @Override
    public String execute(String argumentsJson) {
        String rawFile;
        int line;
        String variable;
        try {
            var parsed = com.google.gson.JsonParser.parseString(argumentsJson).getAsJsonObject();
            rawFile = parsed.has("file") ? parsed.get("file").getAsString() : "";
            line = parsed.has("line") ? parsed.get("line").getAsInt() : -1;
            variable = parsed.has("variable_name") ? parsed.get("variable_name").getAsString() : "";
        } catch (Exception e) {
            return "{\"error\": \"invalid arguments: " + escapeJson(e.getMessage()) + "\"}";
        }
        if (rawFile.isBlank() || line <= 0 || variable.isBlank()) {
            return "{\"error\": \"file/line/variable_name 均为必填\"}";
        }
        if (ctx.codeRepos() == null || ctx.codeRepos().isEmpty()) {
            return "{\"error\": \"未配置代码仓库\"}";
        }

        Path resolved = PathSandbox.resolveWithinRepos(rawFile, ctx.codeRepos());
        if (resolved == null) {
            return "{\"error\": \"路径不在已配置的代码仓库范围内，或文件不存在: " + escapeJson(rawFile) + "\"}";
        }

        TaintTracer.TraceResult result = TaintTracer.trace(ctx.codeRepos(), resolved, line, variable);

        JsonObject out = new JsonObject();
        out.addProperty("heuristic_warning", "regex 启发式回溯，非真实数据流分析，每一跳请用 read_file 核实，"
                + "尤其是别名赋值/字段访问/字符串拼接/多值合并等本工具无法处理的情况");
        out.addProperty("termination_reason", result.terminationReason());
        boolean sourceFound = !result.chain().isEmpty()
                && result.chain().get(result.chain().size() - 1).kind() == TaintTracer.StepKind.SOURCE_MATCH;
        out.addProperty("source_found", sourceFound);

        JsonArray chainArr = new JsonArray();
        for (TaintTracer.TraceStep step : result.chain()) {
            JsonObject s = new JsonObject();
            s.addProperty("file", step.file().toString());
            s.addProperty("line", step.line());
            s.addProperty("variable", step.variable());
            s.addProperty("kind", step.kind().name());
            s.addProperty("snippet", step.snippet());
            chainArr.add(s);
        }
        out.add("chain", chainArr);

        JsonArray otherArr = new JsonArray();
        if (result.otherCallSitesNotTraced() != null) {
            result.otherCallSitesNotTraced().forEach(otherArr::add);
        }
        out.add("other_call_sites_not_traced", otherArr);
        if (otherArr.size() > 0) {
            out.addProperty("note", "还有其它调用处未追踪（只追了第一个），如需完整覆盖可对这些位置重复调用本工具。");
        }

        return out.toString();
    }

    private static String escapeJson(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n");
    }
}
