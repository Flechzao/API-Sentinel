package com.flechazo.apisentinel.ai.agent.tool;

import com.flechazo.apisentinel.ai.agent.FindingEvidenceStore;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

/**
 * Read-side counterpart to {@link UpdateAnalysisNotesTool}.
 *
 * <p>P2-7: lets the agent read back its own persisted findings after context
 * compaction has evicted them from the conversation. Pre-P2-7, once
 * {@code compactIfNeeded} shortened old tool results, the only way to
 * recover the data was to re-call the original tools (double cost:
 * re-execute + re-send the results). With this tool the agent reads its
 * own notes in one cheap call.
 *
 * <p>Optional filters:
 * <ul>
 *   <li>{@code level} — only return findings at this confidence level
 *       (CONFIRMED / SUSPECTED / NEGATIVE / NOTE)</li>
 *   <li>{@code category} — only return findings in this vulnerability
 *       category (SQL_INJECTION / XSS / …)</li>
 *   <li>{@code action} — {@code "progress"} returns the free-text progress
 *       notes (running narrative) instead of structured findings. Pair with
 *       {@code sinceWindow} to recover only what was written after a given
 *       context-window rollover.</li>
 * </ul>
 * No arguments → return all findings (same as the system-prompt-injected
 * summary, but available on-demand after compaction rather than only at
 * injection time).
 */
public class ReadAnalysisNotesTool implements AgentTool {

    private final FindingEvidenceStore findingStore;

    public ReadAnalysisNotesTool(FindingEvidenceStore findingStore) {
        this.findingStore = findingStore;
    }

    @Override
    public String name() { return "read_analysis_notes"; }

    @Override
    public String description() {
        return "Read back your previously recorded security findings. "
             + "Use this after context compaction to recover findings you "
             + "recorded earlier via update_analysis_notes but that were "
             + "evicted from the conversation. "
             + "Optional: 'action'='progress' returns your free-text progress "
             + "notes (hypothesis / blockers / failed payloads) — pair with "
             + "'sinceWindow' to recover only notes written after a given "
             + "context-window rollover. "
             + "Findings filters: 'level' (CONFIRMED/SUSPECTED/NEGATIVE/NOTE), "
             + "'category' (SQL_INJECTION/XSS/SSRF/IDOR/...). "
             + "No arguments → return all findings.";
    }

    @Override
    public JsonObject inputSchema() {
        JsonObject schema = new JsonObject();
        schema.addProperty("type", "object");
        JsonObject props = new JsonObject();

        JsonObject levelProp = new JsonObject();
        levelProp.addProperty("type", "string");
        levelProp.addProperty("description",
                "Optional: filter by confidence level "
                + "(CONFIRMED, SUSPECTED, NEGATIVE, NOTE). "
                + "Omit to return all levels.");
        props.add("level", levelProp);

        JsonObject categoryProp = new JsonObject();
        categoryProp.addProperty("type", "string");
        categoryProp.addProperty("description",
                "Optional: filter by vulnerability category "
                + "(SQL_INJECTION, XSS, SSRF, IDOR, PATH_TRAVERSAL, "
                + "COMMAND_INJECTION, AUTH_BYPASS, BUSINESS_LOGIC, "
                + "INFO_DISCLOSURE, OTHER). Omit to return all categories.");
        props.add("category", categoryProp);

        JsonObject actionProp = new JsonObject();
        actionProp.addProperty("type", "string");
        actionProp.addProperty("description",
                "Optional: 'progress' returns free-text progress notes instead of "
                + "structured findings. Default: return findings.");
        props.add("action", actionProp);

        JsonObject sinceWindowProp = new JsonObject();
        sinceWindowProp.addProperty("type", "integer");
        sinceWindowProp.addProperty("description",
                "Optional (with action='progress'): only return progress notes "
                + "written in a context-window id after this one — used to "
                + "recover just what the current window is missing after a rollover.");
        props.add("sinceWindow", sinceWindowProp);

        schema.add("properties", props);
        return schema;
    }

    @Override
    public String execute(String argumentsJson) {
        String action = null;
        String levelFilter = null;
        String categoryFilter = null;
        int sinceWindow = -1;
        if (argumentsJson != null && !argumentsJson.isBlank()) {
            try {
                JsonObject args = com.google.gson.JsonParser.parseString(argumentsJson).getAsJsonObject();
                if (args.has("action") && !args.get("action").isJsonNull()) {
                    action = args.get("action").getAsString().trim().toLowerCase();
                }
                if (args.has("level") && !args.get("level").isJsonNull()) {
                    levelFilter = args.get("level").getAsString().trim().toUpperCase();
                }
                if (args.has("category") && !args.get("category").isJsonNull()) {
                    categoryFilter = args.get("category").getAsString().trim().toUpperCase();
                }
                if (args.has("sinceWindow") && !args.get("sinceWindow").isJsonNull()) {
                    sinceWindow = args.get("sinceWindow").getAsInt();
                }
            } catch (Exception ignored) {
                // Malformed args → return all findings (no filter).
            }
        }

        // Free-text progress notes path.
        if ("progress".equals(action)) {
            var notes = sinceWindow >= 0
                    ? findingStore.listProgress(sinceWindow)
                    : findingStore.allProgress();
            JsonArray arr = new JsonArray();
            for (var n : notes) {
                JsonObject o = new JsonObject();
                o.addProperty("window", n.windowId());
                o.addProperty("timestamp", n.timestamp());
                o.addProperty("text", n.text());
                arr.add(o);
            }
            JsonObject out = new JsonObject();
            out.addProperty("action", "progress");
            out.addProperty("count", arr.size());
            out.add("progress", arr);
            if (arr.size() == 0) {
                out.addProperty("note", "No progress notes recorded"
                        + (sinceWindow >= 0 ? " for window > " + sinceWindow : "")
                        + ". Use update_analysis_notes(action=progress) to record your running state.");
            }
            return out.toString();
        }

        var allFindings = findingStore.getAllFindings();
        JsonArray arr = new JsonArray();
        for (var f : allFindings) {
            if (levelFilter != null && !levelFilter.equalsIgnoreCase(f.level().name())) continue;
            if (categoryFilter != null && !categoryFilter.equalsIgnoreCase(f.category().name())) continue;

            JsonObject o = new JsonObject();
            o.addProperty("id", f.id());
            o.addProperty("category", f.category().name());
            o.addProperty("parameter", f.parameter());
            o.addProperty("evidence", f.evidence());
            o.addProperty("level", f.level().name());
            o.addProperty("source", f.sourceTool());
            arr.add(o);
        }

        JsonObject out = new JsonObject();
        out.addProperty("count", arr.size());
        out.add("findings", arr);
        if (arr.size() == 0) {
            out.addProperty("note", "No findings recorded yet. Use update_analysis_notes to record discoveries.");
        }
        return out.toString();
    }
}
