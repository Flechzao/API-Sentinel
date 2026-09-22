package com.flechazo.apisentinel.ai.agent.tool;

import com.flechazo.apisentinel.codeindex.RepoGrepper;
import com.flechazo.apisentinel.config.CodeRepo;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

/**
 * Regex search across indexed code repositories, scoped to whichever repos
 * declare a domain matching the current entry (same scoping SearchSourceCodeTool
 * uses) — falls back to searching all configured repos only if none of them
 * declare a matching domain (mirrors CodeIndexService.findByPathAndDomain's
 * fallback, e.g. for a single-repo setup where the user never bothered to
 * configure per-repo domains). Without this, a multi-repo setup makes every
 * grep_repo call search unrelated projects too, which is confusing for the
 * model (and shows up as it noticing results "span multiple projects").
 * Complements read_file: use this first when you know roughly what you're
 * looking for (a class name, an annotation, a config key) but not which file
 * it's in.
 */
public class GrepRepoTool implements AgentTool {

    private static final int DEFAULT_MAX_RESULTS = 50;
    private static final int MAX_RESULTS_CAP = 200;
    private static final int DEFAULT_CONTEXT_LINES = 2;

    private final ToolContext ctx;

    public GrepRepoTool(ToolContext ctx) {
        this.ctx = ctx;
    }

    @Override
    public String name() { return "grep_repo"; }

    @Override
    public boolean isReadOnly() { return true; }

    @Override
    public String description() {
        return "Search all indexed source code repositories for a regex pattern — e.g. find a "
             + "security filter/interceptor chain, all callers of a DAO method, or a config key. "
             + "Returns matching file paths, line numbers, and surrounding context. Free, no AI cost.";
    }

    @Override
    public JsonObject inputSchema() {
        JsonObject schema = new JsonObject();
        schema.addProperty("type", "object");
        JsonObject props = new JsonObject();

        JsonObject patternProp = new JsonObject();
        patternProp.addProperty("type", "string");
        patternProp.addProperty("description", "Java regex to search for (e.g. a class or method name).");
        props.add("pattern", patternProp);

        JsonObject globProp = new JsonObject();
        globProp.addProperty("type", "string");
        globProp.addProperty("description", "Optional glob filter on the file's path relative to the repo "
                + "root. A pattern with no \"/\" matches at any depth (e.g. \"*.java\" matches any .java file "
                + "anywhere, same as before). A pattern containing \"/\" is a real directory-scoped glob, "
                + "e.g. \"src/**/controller/*.java\" or \"**/test/**\" to target/exclude a subtree.");
        props.add("path_glob", globProp);

        JsonObject maxProp = new JsonObject();
        maxProp.addProperty("type", "integer");
        maxProp.addProperty("description", "Max matches to return (default " + DEFAULT_MAX_RESULTS + ", capped at " + MAX_RESULTS_CAP + ").");
        props.add("max_results", maxProp);

        JsonObject ctxProp = new JsonObject();
        ctxProp.addProperty("type", "integer");
        ctxProp.addProperty("description", "Lines of context around each match (default " + DEFAULT_CONTEXT_LINES + ").");
        props.add("context_lines", ctxProp);

        JsonObject caseProp = new JsonObject();
        caseProp.addProperty("type", "boolean");
        caseProp.addProperty("description", "Case-insensitive matching (default false).");
        props.add("case_insensitive", caseProp);

        JsonObject multilineProp = new JsonObject();
        multilineProp.addProperty("type", "boolean");
        multilineProp.addProperty("description", "When true, matches against each file's full content so the "
                + "pattern can span multiple lines (e.g. a try/catch block or a multi-line method signature). "
                + "Default false (line-by-line matching).");
        props.add("multiline", multilineProp);

        schema.add("properties", props);
        JsonArray required = new JsonArray();
        required.add("pattern");
        schema.add("required", required);
        return schema;
    }

    @Override
    public String execute(String argumentsJson) {
        String patternStr;
        String pathGlob = null;
        int maxResults = DEFAULT_MAX_RESULTS;
        int contextLines = DEFAULT_CONTEXT_LINES;
        boolean caseInsensitive = false;
        boolean multiline = false;
        try {
            JsonObject parsed = com.google.gson.JsonParser.parseString(argumentsJson).getAsJsonObject();
            patternStr = parsed.has("pattern") ? parsed.get("pattern").getAsString() : "";
            if (parsed.has("path_glob") && !parsed.get("path_glob").isJsonNull()) {
                pathGlob = parsed.get("path_glob").getAsString();
            }
            if (parsed.has("max_results") && !parsed.get("max_results").isJsonNull()) {
                maxResults = Math.min(MAX_RESULTS_CAP, Math.max(1, parsed.get("max_results").getAsInt()));
            }
            if (parsed.has("context_lines") && !parsed.get("context_lines").isJsonNull()) {
                contextLines = Math.min(10, Math.max(0, parsed.get("context_lines").getAsInt()));
            }
            if (parsed.has("case_insensitive") && !parsed.get("case_insensitive").isJsonNull()) {
                caseInsensitive = parsed.get("case_insensitive").getAsBoolean();
            }
            if (parsed.has("multiline") && !parsed.get("multiline").isJsonNull()) {
                multiline = parsed.get("multiline").getAsBoolean();
            }
        } catch (Exception e) {
            return "{\"error\": \"invalid arguments: " + escapeJson(e.getMessage()) + "\"}";
        }

        if (patternStr.isBlank()) {
            return "{\"error\": \"pattern must not be empty\"}";
        }
        if (ctx.codeRepos() == null || ctx.codeRepos().isEmpty()) {
            return "{\"error\": \"no source code repositories configured\"}";
        }

        Pattern pattern;
        try {
            int flags = caseInsensitive ? Pattern.CASE_INSENSITIVE : 0;
            if (multiline) flags |= Pattern.DOTALL;
            // P2-9: ReDoS guard — reject nested quantifiers before
            // compiling, so an adversarial pattern can't hang the agent.
            pattern = com.flechazo.apisentinel.util.RegexSafety.safeCompile(patternStr, flags);
        } catch (PatternSyntaxException e) {
            return "{\"error\": \"invalid regex: " + escapeJson(e.getMessage()) + "\"}";
        }

        RepoGrepper.GrepOutcome outcome = RepoGrepper.searchEx(
                reposForCurrentDomain(), pattern, pathGlob, maxResults, contextLines, multiline);

        // P0-12 hardening: surface repo-unavailability explicitly so the
        // LLM sees "I couldn't read the repo" rather than "match_count: 0"
        // — the latter looks like a clean bill of health and drives the
        // agent to conclude "this code has no such sink" when the truth
        // is "we had no access to check".
        if (!outcome.isAvailable()) {
            return "{\"error\": \"repo_unavailable — " + escapeJson(outcome.unavailableReason())
                    + ". Re-check the repository path and permissions in Settings → Code Repos. "
                    + "Do NOT conclude that the sink is absent; the search simply couldn't run.\"}";
        }

        List<RepoGrepper.GrepMatch> matches = outcome.matches();
        JsonObject result = new JsonObject();
        result.addProperty("pattern", patternStr);
        result.addProperty("match_count", matches.size());
        result.addProperty("truncated", matches.size() >= maxResults);
        JsonArray arr = new JsonArray();
        for (RepoGrepper.GrepMatch m : matches) {
            JsonObject mo = new JsonObject();
            mo.addProperty("file", m.file().toString());
            mo.addProperty("line", m.line());
            mo.addProperty("context", m.context());
            arr.add(mo);
        }
        result.add("matches", arr);
        return result.toString();
    }

    /** Repos whose configured domain(s) match the current entry; falls back
     *  to all configured repos if none declare a matching domain. */
    private List<CodeRepo> reposForCurrentDomain() {
        String domain = ctx.entry() != null ? ctx.entry().getDomain() : null;
        if (domain == null || domain.isEmpty()) return ctx.codeRepos();
        List<CodeRepo> matching = new ArrayList<>();
        for (CodeRepo repo : ctx.codeRepos()) {
            if (repo.matchesDomain(domain)) matching.add(repo);
        }
        return matching.isEmpty() ? ctx.codeRepos() : matching;
    }

    private static String escapeJson(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n");
    }
}
