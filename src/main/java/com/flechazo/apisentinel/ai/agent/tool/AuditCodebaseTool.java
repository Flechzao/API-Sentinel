package com.flechazo.apisentinel.ai.agent.tool;

import com.flechazo.apisentinel.codeindex.SinkAnnotator;
import com.flechazo.apisentinel.codeindex.SinkMap;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Global codebase audit entry point (Claude-style white-box-first). Returns the
 * full list of dangerous sinks discovered by SinkMap across all indexed repos,
 * grouped by file, each annotated with its sink type and a backward-taint-tracing
 * hint. This gives the agent a whole-repo view so it can proactively hunt
 * vulnerabilities (trace each sink back to its source) instead of only analyzing
 * the single endpoint it was handed. Free, no AI cost, no requests sent.
 */
public class AuditCodebaseTool implements AgentTool {

    private static final int DEFAULT_MAX_SINKS = 80;
    private static final int MAX_SINKS_CAP = 300;

    private final ToolContext ctx;

    public AuditCodebaseTool(ToolContext ctx) {
        this.ctx = ctx;
    }

    @Override
    public String name() { return "audit_codebase"; }

    @Override
    public String description() {
        return "Global white-box audit: list ALL dangerous sinks (command exec / SQL / file access / "
             + "deserialization / SSRF / weak crypto / insecure RNG) found by static analysis across the "
             + "indexed code repositories, grouped by file, each with its type, line, code snippet and a "
             + "backward-taint-tracing hint. Use this to get a whole-repo view and proactively hunt "
             + "vulnerabilities: pick high-risk sinks, read their code (read_file), trace the interpolated "
             + "variables back to their (possibly user-controlled, possibly stored) source, then map to the "
             + "endpoint that reaches them and verify with traffic. Free, no requests sent. "
             + "Optional 'sink_type' filter (command|sql|file_access|deserialization|ssrf|crypto|insecure_random).";
    }

    @Override
    public JsonObject inputSchema() {
        JsonObject schema = new JsonObject();
        schema.addProperty("type", "object");
        JsonObject props = new JsonObject();

        JsonObject typeProp = new JsonObject();
        typeProp.addProperty("type", "string");
        typeProp.addProperty("description", "Optional sink type filter: command, sql, file_access, "
                + "deserialization, ssrf, crypto, insecure_random. Omit for all types.");
        props.add("sink_type", typeProp);

        JsonObject maxProp = new JsonObject();
        maxProp.addProperty("type", "integer");
        maxProp.addProperty("description", "Max sinks to return (default " + DEFAULT_MAX_SINKS + ", cap " + MAX_SINKS_CAP + ").");
        props.add("max_results", maxProp);

        schema.add("properties", props);
        return schema;
    }

    @Override
    public String execute(String argumentsJson) {
        var codeIndex = ctx.codeIndexService();
        if (codeIndex == null) {
            return "{\"error\": \"No code index service configured.\"}";
        }
        SinkMap sinkMap = codeIndex.getSinkMap();
        if (sinkMap == null || sinkMap.totalSinkCount() == 0) {
            return "{\"error\": \"No sinks indexed. Index a code repository first (Settings -> Code Repos).\"}";
        }

        // Parse optional filters
        SinkMap.SinkType typeFilter = null;
        int maxResults = DEFAULT_MAX_SINKS;
        try {
            JsonObject args = JsonParser.parseString(argumentsJson).getAsJsonObject();
            if (args.has("sink_type") && !args.get("sink_type").getAsString().isBlank()) {
                typeFilter = parseType(args.get("sink_type").getAsString());
            }
            if (args.has("max_results")) {
                maxResults = Math.min(Math.max(args.get("max_results").getAsInt(), 1), MAX_SINKS_CAP);
            }
        } catch (Exception ignored) {}

        // Explicit sink_type filter wins; otherwise, if the high-risk-only scope
        // control is enabled (cost control), restrict to the high-risk sink types.
        // Default (flag off) audits every sink.
        List<SinkMap.SinkEntry> sinks;
        if (typeFilter != null) {
            sinks = sinkMap.allSinksOfType(typeFilter);
        } else if (ctx.pipelineConfig() != null && ctx.pipelineConfig().auditHighRiskOnly()) {
            sinks = new ArrayList<>();
            sinks.addAll(sinkMap.allSinksOfType(SinkMap.SinkType.COMMAND));
            sinks.addAll(sinkMap.allSinksOfType(SinkMap.SinkType.SQL));
            sinks.addAll(sinkMap.allSinksOfType(SinkMap.SinkType.DESERIALIZATION));
        } else {
            sinks = sinkMap.allSinks();
        }

        // Group by file
        Map<String, List<SinkMap.SinkEntry>> byFile = new LinkedHashMap<>();
        for (SinkMap.SinkEntry s : sinks) {
            byFile.computeIfAbsent(s.file(), k -> new ArrayList<>()).add(s);
        }

        JsonObject out = new JsonObject();
        out.addProperty("total_sinks", sinks.size());
        out.addProperty("files_with_sinks", byFile.size());
        out.addProperty("note", "Pick high-risk sinks (command/sql/deserialization), read their code with "
                + "read_file, trace interpolated variables back to their source (use find_callers if the value "
                + "comes from stored data), map to the endpoint that reaches the sink, then verify with traffic.");

        JsonArray filesArr = new JsonArray();
        int emitted = 0;
        outer:
        for (Map.Entry<String, List<SinkMap.SinkEntry>> e : byFile.entrySet()) {
            JsonObject fo = new JsonObject();
            fo.addProperty("file", e.getKey());
            JsonArray sinksArr = new JsonArray();
            for (SinkMap.SinkEntry s : e.getValue()) {
                if (emitted >= maxResults) break outer;
                JsonObject so = new JsonObject();
                so.addProperty("line", s.line());
                so.addProperty("type", s.type().name());
                so.addProperty("label", SinkAnnotator.label(s.type()));
                String hint = SinkAnnotator.traceHint(s.type());
                if (!hint.isEmpty()) so.addProperty("trace_hint", hint);
                String snippet = s.snippet();
                if (snippet != null && snippet.length() > 160) snippet = snippet.substring(0, 157) + "...";
                so.addProperty("snippet", snippet);
                sinksArr.add(so);
                emitted++;
            }
            fo.add("sinks", sinksArr);
            filesArr.add(fo);
        }
        out.add("files", filesArr);
        if (sinks.size() > emitted) {
            out.addProperty("truncated", true);
            out.addProperty("returned", emitted);
        }
        return out.toString();
    }

    private static SinkMap.SinkType parseType(String s) {
        return switch (s.trim().toLowerCase()) {
            case "command", "cmd", "rce" -> SinkMap.SinkType.COMMAND;
            case "sql", "sqli" -> SinkMap.SinkType.SQL;
            case "file_access", "file", "path_traversal", "lfi" -> SinkMap.SinkType.FILE_ACCESS;
            case "deserialization", "deser" -> SinkMap.SinkType.DESERIALIZATION;
            case "ssrf" -> SinkMap.SinkType.SSRF;
            case "crypto", "weak_crypto" -> SinkMap.SinkType.CRYPTO;
            case "insecure_random", "rng" -> SinkMap.SinkType.INSECURE_RANDOM;
            default -> null;
        };
    }
}
