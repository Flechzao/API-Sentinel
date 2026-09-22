package com.flechazo.apisentinel.ai.agent.tool;

import com.flechazo.apisentinel.detection.template.DetectionTemplate;
import com.flechazo.apisentinel.detection.template.TemplateLoader;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

/**
 * custom_detection — 自定义检测模板工具
 *
 * 使用 YAML 模板执行自定义检测规则（参考 Nuclei）。
 *
 * 支持的操作：
 * - `list` — 列出所有可用模板
 * - `run` — 运行指定模板对目标进行检测
 * - `reload` — 重新加载模板目录
 *
 * @since 1.2.0
 */
public class CustomDetectionTool implements AgentTool {

    private final ToolContext ctx;
    private final TemplateLoader loader;

    public CustomDetectionTool(ToolContext ctx, Path templateDir) {
        this.ctx = ctx;
        this.loader = new TemplateLoader(templateDir, ctx.logger());
        this.loader.loadAll();
    }

    @Override
    public String name() { return "custom_detection"; }

    @Override
    public String description() {
        return "Run custom detection templates (YAML-based, similar to Nuclei). "
             + "Templates define matchers (regex, word, status) to detect specific vulnerability patterns. "
             + "Actions: 'list' (show all templates), 'run' (execute a template), 'reload' (refresh templates). "
             + "Templates are loaded from the custom-templates/ directory. Zero LLM cost.";
    }

    @Override
    public JsonObject inputSchema() {
        JsonObject schema = new JsonObject();
        schema.addProperty("type", "object");
        JsonObject props = new JsonObject();

        props.add("action", prop("string",
                "Action: 'list', 'run', or 'reload'"));

        props.add("template_id", prop("string",
                "Template ID to run (required for action='run')"));

        props.add("tag", prop("string",
                "Filter templates by tag (optional for action='list')"));

        props.add("severity", prop("string",
                "Filter templates by severity (optional for action='list')"));

        schema.add("properties", props);
        return schema;
    }

    @Override
    public String execute(String argumentsJson) {
        JsonObject args;
        try {
            args = JsonParser.parseString(argumentsJson).getAsJsonObject();
        } catch (Exception e) {
            return err("Invalid JSON: " + e.getMessage());
        }

        String action = str(args, "action", "list");
        String templateId = str(args, "template_id", null);
        String tag = str(args, "tag", null);
        String severity = str(args, "severity", null);

        return switch (action.toLowerCase()) {
            case "list" -> executeList(tag, severity);
            case "run" -> executeRun(templateId);
            case "reload" -> executeReload();
            default -> err("Unknown action: " + action + ". Use: list, run, or reload");
        };
    }

    private String executeList(String tag, String severity) {
        List<DetectionTemplate> templates;

        if (tag != null && !tag.isEmpty()) {
            templates = loader.getByTag(tag);
        } else if (severity != null && !severity.isEmpty()) {
            templates = loader.getBySeverity(severity);
        } else {
            templates = loader.getAll();
        }

        JsonObject out = new JsonObject();
        out.addProperty("success", true);
        out.addProperty("action", "list");
        out.addProperty("count", templates.size());

        JsonArray arr = new JsonArray();
        for (DetectionTemplate t : templates) {
            JsonObject to = new JsonObject();
            to.addProperty("id", t.id());
            to.addProperty("name", t.name());
            to.addProperty("severity", t.severity());
            to.addProperty("type", t.type());
            to.addProperty("matchers", t.matchers().size());
            if (t.tags() != null) {
                to.addProperty("tags", String.join(", ", t.tags()));
            }
            to.addProperty("summary", t.summary());
            arr.add(to);
        }
        out.add("templates", arr);

        out.add("stats", toJsonObject(loader.getStats()));
        return out.toString();
    }

    private String executeRun(String templateId) {
        if (templateId == null || templateId.isEmpty()) {
            return err("template_id is required for action='run'");
        }

        DetectionTemplate template = loader.getById(templateId);
        if (template == null) {
            return err("Template not found: " + templateId + ". Use action='list' to see available templates.");
        }

        // Get the current API entry's response to test against
        var entry = ctx.entry();
        if (entry == null) {
            return err("No API entry available. This tool must be run in the context of an API analysis.");
        }

        String response = entry.getLastRawResponse();
        if (response == null || response.isEmpty()) {
            return err("No response available to test against.");
        }

        // Run matchers
        List<String> matchedMatchers = new ArrayList<>();
        boolean overallMatch = false;

        for (DetectionTemplate.Matcher matcher : template.matchers()) {
            boolean matched = evaluateMatcher(matcher, response);
            if (matcher.negative()) {
                matched = !matched; // Invert for negative matchers
            }
            if (matched) {
                matchedMatchers.add(matcher.describe());
                overallMatch = true;
            }
        }

        JsonObject out = new JsonObject();
        out.addProperty("success", true);
        out.addProperty("action", "run");
        out.addProperty("template_id", template.id());
        out.addProperty("template_name", template.name());
        out.addProperty("matched", overallMatch);
        out.addProperty("matchers_matched", matchedMatchers.size());

        if (overallMatch) {
            out.addProperty("severity", template.severity());
            out.addProperty("finding", template.name() + " detected");
            if (template.description() != null) {
                out.addProperty("description", template.description());
            }
            if (template.remediation() != null) {
                out.addProperty("remediation", template.remediation());
            }
        }

        JsonArray matchersArr = new JsonArray();
        for (String m : matchedMatchers) matchersArr.add(m);
        out.add("matched_matchers", matchersArr);

        if (ctx.logger() != null) {
            ctx.logger().info("[custom_detection] Template %s: %s (%d/%d matchers)",
                    template.id(), overallMatch ? "MATCHED" : "no match",
                    matchedMatchers.size(), template.matchers().size());
        }

        return out.toString();
    }

    private String executeReload() {
        loader.reload();

        JsonObject out = new JsonObject();
        out.addProperty("success", true);
        out.addProperty("action", "reload");
        out.addProperty("message", "Templates reloaded successfully");
        out.add("stats", toJsonObject(loader.getStats()));
        return out.toString();
    }

    /**
     * 评估单个匹配器
     */
    private boolean evaluateMatcher(DetectionTemplate.Matcher matcher, String response) {
        if (!matcher.isValidType()) return false;

        String target = extractPart(matcher.part(), response);

        return switch (matcher.type()) {
            case "regex" -> evaluateRegex(matcher.pattern(), target);
            case "word" -> evaluateWords(matcher.words(), target, matcher.condition());
            case "status" -> evaluateStatus(matcher.status(), response);
            case "dsl" -> false; // DSL not implemented yet
            default -> false;
        };
    }

    /** P1 ReDoS 防护：用户正则最大长度，过长更可能是攻击而非检测规则。 */
    private static final int MAX_REGEX_PATTERN_LEN = 2000;
    /** P1 ReDoS 防护：匹配前截断目标，避免对超大响应做正则全扫。 */
    private static final int MAX_REGEX_TARGET_LEN = 100_000;
    /**
     * 灾难性回溯特征：一个内部含量词的捕获组紧跟量词（如 {@code (a+)+}、{@code (x*)*}）。
     * 这是教科书级 ReDoS 形态。仅命中"组内含量词 + 组外紧跟量词"，误报率低；
     * 现有内置模板（纯 alternation、无嵌套量词）不受影响。
     */
    private static final java.util.regex.Pattern CATACLYSMIC_BACKTRACK =
            java.util.regex.Pattern.compile("\\([^()]*[+*?][^()]*\\)[+*?{]");
    /**
     * P3 性能：编译后的 Pattern 缓存。同一 pattern 字符串在多次 run/多响应间复用，
     * 避免每次 evaluateRegex 都重新 Pattern.compile。Pattern 本身线程安全（Matcher 非线程安全，
     * 但此处每次调用新建 matcher）。ConcurrentHashMap 保证并发安全。
     */
    private static final java.util.Map<String, java.util.regex.Pattern> COMPILED_PATTERNS =
            new java.util.concurrent.ConcurrentHashMap<>();

    private boolean evaluateRegex(String pattern, String target) {
        if (pattern == null || target == null) return false;
        if (pattern.length() > MAX_REGEX_PATTERN_LEN) {
            if (ctx.logger() != null) {
                ctx.logger().warn("[custom_detection] Regex pattern too long (%d > %d), skipped",
                        pattern.length(), MAX_REGEX_PATTERN_LEN);
            }
            return false;
        }
        if (CATACLYSMIC_BACKTRACK.matcher(pattern).find()) {
            if (ctx.logger() != null) {
                ctx.logger().warn("[custom_detection] Regex rejected (potential ReDoS, nested quantifier): %s", pattern);
            }
            return false;
        }
        // 截断超大目标，把正则扫描成本限制在常数上界内
        String boundedTarget = target.length() > MAX_REGEX_TARGET_LEN
                ? target.substring(0, MAX_REGEX_TARGET_LEN) : target;
        try {
            // 复用编译后的 Pattern（首次遇到时编译并缓存），避免重复编译开销
            java.util.regex.Pattern compiled = COMPILED_PATTERNS.computeIfAbsent(
                    pattern, p -> Pattern.compile(p, Pattern.CASE_INSENSITIVE));
            return compiled.matcher(boundedTarget).find();
        } catch (Exception e) {
            if (ctx.logger() != null) {
                ctx.logger().warn("[custom_detection] Invalid regex: %s", pattern);
            }
            return false;
        }
    }

    private boolean evaluateWords(List<String> words, String target, String condition) {
        if (words == null || target == null) return false;
        String lowerTarget = target.toLowerCase();

        if ("and".equalsIgnoreCase(condition)) {
            return words.stream().allMatch(w -> lowerTarget.contains(w.toLowerCase()));
        } else { // "or"
            return words.stream().anyMatch(w -> lowerTarget.contains(w.toLowerCase()));
        }
    }

    private boolean evaluateStatus(Integer expectedStatus, String response) {
        if (expectedStatus == null || response == null) return false;
        // Extract status code from response (e.g., "HTTP/1.1 200 OK")
        String[] lines = response.split("\n");
        if (lines.length > 0) {
            String[] parts = lines[0].split("\\s+");
            if (parts.length >= 2) {
                try {
                    int actualStatus = Integer.parseInt(parts[1]);
                    return actualStatus == expectedStatus;
                } catch (NumberFormatException ignored) {}
            }
        }
        return false;
    }

    private String extractPart(String part, String response) {
        if (part == null || "all".equals(part)) return response;

        if ("body".equals(part)) {
            int bodyStart = response.indexOf("\r\n\r\n");
            if (bodyStart < 0) bodyStart = response.indexOf("\n\n");
            if (bodyStart >= 0) {
                return response.substring(bodyStart + 4);
            }
        } else if ("headers".equals(part)) {
            int bodyStart = response.indexOf("\r\n\r\n");
            if (bodyStart < 0) bodyStart = response.indexOf("\n\n");
            if (bodyStart >= 0) {
                return response.substring(0, bodyStart);
            }
        }

        return response;
    }

    // ==================== Helpers ====================

    private static JsonObject prop(String type, String desc) {
        JsonObject p = new JsonObject();
        p.addProperty("type", type);
        p.addProperty("description", desc);
        return p;
    }

    private static String str(JsonObject obj, String key, String def) {
        if (obj.has(key) && !obj.get(key).isJsonNull()) {
            return obj.get(key).getAsString();
        }
        return def;
    }

    private static JsonObject toJsonObject(java.util.Map<String, Object> map) {
        JsonObject obj = new JsonObject();
        for (var entry : map.entrySet()) {
            Object value = entry.getValue();
            if (value instanceof String) {
                obj.addProperty(entry.getKey(), (String) value);
            } else if (value instanceof Integer) {
                obj.addProperty(entry.getKey(), (Integer) value);
            } else if (value instanceof java.util.Map) {
                @SuppressWarnings("unchecked")
                var nestedMap = (java.util.Map<String, Object>) value;
                obj.add(entry.getKey(), toJsonObject(nestedMap));
            }
        }
        return obj;
    }

    private static String err(String msg) {
        JsonObject o = new JsonObject();
        o.addProperty("success", false);
        o.addProperty("error", msg);
        return o.toString();
    }
}
