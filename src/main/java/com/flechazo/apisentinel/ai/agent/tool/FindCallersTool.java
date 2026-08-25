package com.flechazo.apisentinel.ai.agent.tool;

import com.flechazo.apisentinel.codeindex.RepoGrepper;
import com.flechazo.apisentinel.config.CodeRepo;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import java.util.List;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

public class FindCallersTool implements AgentTool {

    private final ToolContext ctx;

    private static final Pattern DEFINITION_PATTERN = Pattern.compile(
            "(?:public|private|protected|internal)\\s+(?:static\\s+)?(?:final\\s+)?(?:suspend\\s+)?\\S+\\s+\\w+\\s*\\(");

    public FindCallersTool(ToolContext ctx) {
        this.ctx = ctx;
    }

    @Override
    public String name() {
        return "find_callers";
    }

    @Override
    public String description() {
        return "查找一个方法的所有调用处（call sites），排除定义本身。用于评估某个方法的调用面、找到入口链路。免费。";
    }

    @Override
    public JsonObject inputSchema() {
        JsonObject schema = new JsonObject();
        schema.addProperty("type", "object");
        JsonObject props = new JsonObject();

        JsonObject methodProp = new JsonObject();
        methodProp.addProperty("type", "string");
        methodProp.addProperty("description", "要查找调用者的方法名（如 checkPermission, executeQuery）");
        props.add("method_name", methodProp);

        JsonObject maxProp = new JsonObject();
        maxProp.addProperty("type", "integer");
        maxProp.addProperty("description", "最大结果数，默认 30，上限 100");
        maxProp.addProperty("default", 30);
        props.add("max_results", maxProp);

        JsonObject globProp = new JsonObject();
        globProp.addProperty("type", "string");
        globProp.addProperty("description", "文件过滤（如 *.java），可选");
        props.add("path_glob", globProp);

        schema.add("properties", props);
        JsonArray required = new JsonArray();
        required.add("method_name");
        schema.add("required", required);
        return schema;
    }

    @Override
    public String execute(String argumentsJson) {
        JsonObject args = JsonParser.parseString(argumentsJson).getAsJsonObject();
        String methodName = args.get("method_name").getAsString().trim();
        int maxResults = args.has("max_results") && !args.get("max_results").isJsonNull()
                ? Math.min(args.get("max_results").getAsInt(), 100) : 30;
        String pathGlob = args.has("path_glob") && !args.get("path_glob").isJsonNull()
                ? args.get("path_glob").getAsString() : null;

        if (methodName.isEmpty()) {
            return "{\"error\": \"method_name 参数不能为空\"}";
        }

        List<CodeRepo> repos = getRepos();
        if (repos.isEmpty()) {
            return "{\"error\": \"未配置代码仓库或无匹配域名的仓库\"}";
        }

        Pattern callPattern = Pattern.compile("\\b" + Pattern.quote(methodName) + "\\s*\\(");
        List<RepoGrepper.GrepMatch> rawResults = RepoGrepper.search(
                repos, callPattern, pathGlob, maxResults + 20, 2);

        List<RepoGrepper.GrepMatch> callers = rawResults.stream()
                .filter(m -> !isDefinitionLine(m.context(), methodName))
                .filter(m -> !m.file().toString().contains("/test/"))
                .limit(maxResults)
                .collect(Collectors.toList());

        JsonObject response = new JsonObject();
        response.addProperty("method_name", methodName);
        response.addProperty("caller_count", callers.size());
        response.addProperty("truncated", rawResults.size() > maxResults + 20);

        JsonArray callersArray = new JsonArray();
        for (RepoGrepper.GrepMatch match : callers) {
            JsonObject caller = new JsonObject();
            caller.addProperty("file", match.file().toString());
            caller.addProperty("line", match.line());
            caller.addProperty("context", match.context());
            callersArray.add(caller);
        }
        response.add("callers", callersArray);

        if (callers.isEmpty()) {
            response.addProperty("hint", "未找到调用处。方法可能仅在定义处出现，或使用了反射/动态调用。");
        }

        return response.toString();
    }

    private boolean isDefinitionLine(String context, String methodName) {
        if (context == null) return false;
        String[] lines = context.split("\n");
        for (String line : lines) {
            String content = line.contains(":") ? line.substring(line.indexOf(':') + 1).trim() : line.trim();
            if (content.contains(methodName) && DEFINITION_PATTERN.matcher(content).find()
                    && content.contains(methodName + "(")) {
                return true;
            }
        }
        return false;
    }

    private List<CodeRepo> getRepos() {
        List<CodeRepo> repos = ctx.codeRepos();
        if (repos == null || repos.isEmpty()) return List.of();
        String domain = ctx.entry() != null ? ctx.entry().getDomain() : null;
        if (domain == null || domain.isEmpty()) return repos;
        List<CodeRepo> matched = repos.stream()
                .filter(r -> r.matchesDomain(domain))
                .collect(Collectors.toList());
        return matched.isEmpty() ? repos : matched;
    }
}
