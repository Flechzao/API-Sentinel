package com.flechazo.apisentinel.ai.agent.tool;

import com.flechazo.apisentinel.codeindex.RepoGrepper;
import com.flechazo.apisentinel.config.CodeRepo;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import java.util.List;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

public class FindDefinitionTool implements AgentTool {

    private final ToolContext ctx;

    public FindDefinitionTool(ToolContext ctx) {
        this.ctx = ctx;
    }

    @Override
    public String name() {
        return "find_definition";
    }

    @Override
    public String description() {
        return "查找一个类名或方法名的定义位置（源文件+行号）。当你从代码中看到一个被调用的类/方法但不知道在哪个文件定义时使用。免费。";
    }

    @Override
    public JsonObject inputSchema() {
        JsonObject schema = new JsonObject();
        schema.addProperty("type", "object");
        JsonObject props = new JsonObject();

        JsonObject nameProp = new JsonObject();
        nameProp.addProperty("type", "string");
        nameProp.addProperty("description", "要查找的类名或方法名（如 UserService, checkPermission）");
        props.add("name", nameProp);

        JsonObject typeProp = new JsonObject();
        typeProp.addProperty("type", "string");
        typeProp.addProperty("description", "查找类型：class（类/接口/枚举定义）、method（方法定义）、any（先找类再找方法）。默认 any");
        typeProp.addProperty("default", "any");
        props.add("type", typeProp);

        JsonObject globProp = new JsonObject();
        globProp.addProperty("type", "string");
        globProp.addProperty("description", "文件过滤（如 *.java），可选");
        props.add("path_glob", globProp);

        schema.add("properties", props);
        JsonArray required = new JsonArray();
        required.add("name");
        schema.add("required", required);
        return schema;
    }

    @Override
    public String execute(String argumentsJson) {
        JsonObject args = JsonParser.parseString(argumentsJson).getAsJsonObject();
        String name = args.get("name").getAsString().trim();
        String type = args.has("type") && !args.get("type").isJsonNull()
                ? args.get("type").getAsString() : "any";
        String pathGlob = args.has("path_glob") && !args.get("path_glob").isJsonNull()
                ? args.get("path_glob").getAsString() : null;

        if (name.isEmpty()) {
            return "{\"error\": \"name 参数不能为空\"}";
        }

        List<CodeRepo> repos = getRepos();
        if (repos.isEmpty()) {
            return "{\"error\": \"未配置代码仓库或无匹配域名的仓库\"}";
        }

        List<RepoGrepper.GrepMatch> results;
        String detectedType;

        if ("class".equals(type)) {
            results = searchClass(repos, name, pathGlob);
            detectedType = "class";
        } else if ("method".equals(type)) {
            results = searchMethod(repos, name, pathGlob);
            detectedType = "method";
        } else {
            results = searchClass(repos, name, pathGlob);
            detectedType = "class";
            if (results.isEmpty()) {
                results = searchMethod(repos, name, pathGlob);
                detectedType = "method";
            }
        }

        results = results.stream()
                .filter(m -> !m.file().toString().contains("/test/"))
                .collect(Collectors.toList());

        JsonObject response = new JsonObject();
        response.addProperty("name", name);
        response.addProperty("type", detectedType);
        response.addProperty("count", results.size());

        JsonArray definitions = new JsonArray();
        for (RepoGrepper.GrepMatch match : results) {
            JsonObject def = new JsonObject();
            def.addProperty("file", match.file().toString());
            def.addProperty("line", match.line());
            def.addProperty("context", match.context());
            definitions.add(def);
        }
        response.add("definitions", definitions);

        if (results.isEmpty()) {
            response.addProperty("hint", "未找到定义。可尝试 grep_repo 用更宽泛的正则搜索。");
        }

        return response.toString();
    }

    private List<RepoGrepper.GrepMatch> searchClass(List<CodeRepo> repos, String name, String pathGlob) {
        Pattern pattern = Pattern.compile(
                "\\b(?:class|interface|enum)\\s+" + Pattern.quote(name) + "\\b");
        return RepoGrepper.search(repos, pattern, pathGlob, 10, 3);
    }

    private List<RepoGrepper.GrepMatch> searchMethod(List<CodeRepo> repos, String name, String pathGlob) {
        Pattern pattern = Pattern.compile(
                "(?:public|private|protected|internal)\\s+(?:static\\s+)?(?:final\\s+)?(?:suspend\\s+)?\\S+\\s+"
                        + Pattern.quote(name) + "\\s*\\(");
        List<RepoGrepper.GrepMatch> results = RepoGrepper.search(repos, pattern, pathGlob, 10, 3);
        if (results.isEmpty()) {
            Pattern pyPattern = Pattern.compile("def\\s+" + Pattern.quote(name) + "\\s*\\(");
            results = RepoGrepper.search(repos, pyPattern, pathGlob, 10, 3);
        }
        if (results.isEmpty()) {
            Pattern jsPattern = Pattern.compile(
                    "(?:function\\s+" + Pattern.quote(name) + "\\s*\\(|"
                            + Pattern.quote(name) + "\\s*[:=]\\s*(?:async\\s+)?(?:function|\\())");
            results = RepoGrepper.search(repos, jsPattern, pathGlob, 10, 3);
        }
        return results;
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
