package com.flechazo.apisentinel.ai.agent.tool;

import com.flechazo.apisentinel.codeindex.PathSandbox;
import com.google.gson.JsonObject;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

/**
 * Generic file-read tool for the LLM to follow a call from a route handler
 * into a service/DAO/middleware/security-config class that search_source_code's
 * fixed ~33-line window didn't cover. Only paths under configured code repos
 * are accessible (enforced by PathSandbox).
 */
public class ReadFileTool implements AgentTool {

    /** Safety cap so one call can't blow the whole context budget on a huge
     *  (e.g. minified/generated) file. */
    private static final int MAX_WINDOW_LINES = 4000;
    private static final int MAX_CONTENT_CHARS = 300_000;

    private final ToolContext ctx;

    public ReadFileTool(ToolContext ctx) {
        this.ctx = ctx;
    }

    @Override
    public String name() { return "read_file"; }

    @Override
    public String description() {
        return "Read a file from an indexed source code repository by path, optionally a specific "
             + "line range. Use this when search_source_code's snippet is too narrow — e.g. to open "
             + "a service/DAO/middleware/security-config class that a controller method calls into. "
             + "Defaults to the whole file (capped at " + MAX_WINDOW_LINES + " lines); for larger "
             + "files, pass start_line/end_line to read further sections. Only paths under configured "
             + "code repos are accessible. Free, no AI cost.";
    }

    @Override
    public JsonObject inputSchema() {
        JsonObject schema = new JsonObject();
        schema.addProperty("type", "object");
        JsonObject props = new JsonObject();

        JsonObject pathProp = new JsonObject();
        pathProp.addProperty("type", "string");
        pathProp.addProperty("description", "File path (absolute, or relative to an indexed repo root).");
        props.add("path", pathProp);

        JsonObject startProp = new JsonObject();
        startProp.addProperty("type", "integer");
        startProp.addProperty("description", "1-based start line (optional; defaults to 1).");
        props.add("start_line", startProp);

        JsonObject endProp = new JsonObject();
        endProp.addProperty("type", "integer");
        endProp.addProperty("description", "1-based end line, inclusive (optional).");
        props.add("end_line", endProp);

        schema.add("properties", props);
        com.google.gson.JsonArray required = new com.google.gson.JsonArray();
        required.add("path");
        schema.add("required", required);
        return schema;
    }

    @Override
    public String execute(String argumentsJson) {
        String path;
        Integer startLine = null;
        Integer endLine = null;
        try {
            JsonObject parsed = com.google.gson.JsonParser.parseString(argumentsJson).getAsJsonObject();
            path = parsed.has("path") ? parsed.get("path").getAsString() : "";
            if (parsed.has("start_line") && !parsed.get("start_line").isJsonNull()) {
                startLine = parsed.get("start_line").getAsInt();
            }
            if (parsed.has("end_line") && !parsed.get("end_line").isJsonNull()) {
                endLine = parsed.get("end_line").getAsInt();
            }
        } catch (Exception e) {
            return "{\"error\": \"invalid arguments: " + escapeJson(e.getMessage()) + "\"}";
        }

        Path resolved = PathSandbox.resolveWithinRepos(path, ctx.codeRepos());
        if (resolved == null) {
            return "{\"error\": \"file not found or outside indexed repo roots: " + escapeJson(path) + "\"}";
        }
        if (Files.isDirectory(resolved)) {
            return "{\"error\": \"path is a directory, not a file: " + escapeJson(path) + "\"}";
        }

        List<String> lines;
        try {
            lines = Files.readAllLines(resolved);
        } catch (Exception e) {
            return "{\"error\": \"failed to read file (likely binary/non-UTF8): " + escapeJson(e.getMessage()) + "\"}";
        }

        int total = lines.size();
        int start = startLine != null ? Math.max(1, startLine) : 1;
        int requestedEnd = endLine != null ? Math.min(total, endLine) : Math.min(total, start + MAX_WINDOW_LINES - 1);
        int end = Math.min(requestedEnd, start + MAX_WINDOW_LINES - 1);
        if (start > total) {
            return "{\"error\": \"start_line " + start + " is beyond file end (" + total + " lines total)\"}";
        }

        StringBuilder content = new StringBuilder();
        boolean charTruncated = false;
        for (int i = start; i <= end; i++) {
            String numbered = String.format("%5d | %s%n", i, lines.get(i - 1));
            if (content.length() + numbered.length() > MAX_CONTENT_CHARS) {
                charTruncated = true;
                end = i - 1;
                break;
            }
            content.append(numbered);
        }

        boolean lineTruncated = end < requestedEnd || (endLine == null && end < total);
        JsonObject result = new JsonObject();
        result.addProperty("file", resolved.toString());
        result.addProperty("start_line", start);
        result.addProperty("end_line", end);
        result.addProperty("total_lines", total);
        result.addProperty("truncated", lineTruncated || charTruncated);
        if (lineTruncated || charTruncated) {
            result.addProperty("hint", "Output capped — pass start_line/end_line to read the remaining "
                    + (total - end) + " lines.");
        }
        result.addProperty("content", content.toString());
        return result.toString();
    }

    private static String escapeJson(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n");
    }
}
