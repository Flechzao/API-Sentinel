package com.flechazo.apisentinel.ai.agent.tool;

import com.flechazo.apisentinel.ai.agent.FindingEvidenceStore;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

/**
 * Meta-tool for agent self-managed memory — inspired by MemGPT's core_memory_append/replace.
 *
 * <p>Allows the agent to explicitly record, update, or annotate security findings
 * during analysis. This is the "pull" side of the FindingEvidenceStore —
 * the agent decides what's important enough to remember.
 *
 * <p>Actions:
 * <ul>
 *   <li><b>add</b> — add a new finding (category + parameter + evidence + level)</li>
 *   <li><b>update</b> — change a finding's confidence level (e.g., SUSPECTED → CONFIRMED)</li>
 *   <li><b>note</b> — add a general observation/note (no specific vulnerability)</li>
 *   <li><b>progress</b> — append free-text running progress (hypothesis / 卡点 / 失败 payload / 已测端点) that survives compaction and context-window rollover</li>
 *   <li><b>checkpoint</b> — append a structured progress checkpoint (same store as progress, for a concise state snapshot)</li>
 * </ul>
 *
 * <p>Example usage:
 * <pre>
 * update_analysis_notes({
 *   "action": "add",
 *   "category": "SQL_INJECTION",
 *   "parameter": "id",
 *   "evidence": "' OR 1=1-- returned all rows (200 vs baseline 404)",
 *   "level": "SUSPECTED"
 * })
 * </pre>
 */
public class UpdateAnalysisNotesTool implements AgentTool {

    private final FindingEvidenceStore findingStore;

    public UpdateAnalysisNotesTool(FindingEvidenceStore findingStore) {
        this.findingStore = findingStore;
    }

    @Override
    public String name() { return "update_analysis_notes"; }

    @Override
    public String description() {
        return "Record or update security findings during analysis. "
             + "Use this to persist important discoveries so they aren't lost when "
             + "the conversation context is compacted. "
             + "Actions: 'add' (new finding), 'update' (change confidence level), "
             + "'note' (general observation), "
             + "'progress' (free-text running progress: hypothesis / 卡点 / 失败 payload / 已测端点, "
             + "survives compaction and context-window rollover), "
             + "'checkpoint' (structured progress snapshot). "
             + "Categories: SQL_INJECTION, XSS, SSRF, IDOR, PATH_TRAVERSAL, "
             + "COMMAND_INJECTION, AUTH_BYPASS, BUSINESS_LOGIC, INFO_DISCLOSURE, etc. "
             + "Levels: CONFIRMED, SUSPECTED, NEGATIVE, NOTE.";
    }

    @Override
    public JsonObject inputSchema() {
        JsonObject schema = new JsonObject();
        schema.addProperty("type", "object");
        JsonObject props = new JsonObject();

        // action
        JsonObject actionProp = new JsonObject();
        actionProp.addProperty("type", "string");
        actionProp.addProperty("description",
                "Action to perform: 'add', 'update', 'note', 'progress', or 'checkpoint'");
        props.add("action", actionProp);

        // text (for progress / checkpoint — free-text running narrative)
        JsonObject textProp = new JsonObject();
        textProp.addProperty("type", "string");
        textProp.addProperty("description",
                "Free-text progress note (for progress/checkpoint): hypothesis, "
                + "blockers, failed payloads, endpoints already tested, what's next. "
                + "Survives compaction and context-window rollover.");
        props.add("text", textProp);

        // category (for add/note)
        JsonObject categoryProp = new JsonObject();
        categoryProp.addProperty("type", "string");
        categoryProp.addProperty("description",
                "Vulnerability category (for add/note): SQL_INJECTION, XSS, SSRF, IDOR, "
                + "PATH_TRAVERSAL, COMMAND_INJECTION, AUTH_BYPASS, BUSINESS_LOGIC, "
                + "INFO_DISCLOSURE, OTHER");
        props.add("category", categoryProp);

        // parameter (for add)
        JsonObject paramProp = new JsonObject();
        paramProp.addProperty("type", "string");
        paramProp.addProperty("description",
                "Parameter or endpoint involved (for add)");
        props.add("parameter", paramProp);

        // evidence (for add/note)
        JsonObject evidenceProp = new JsonObject();
        evidenceProp.addProperty("type", "string");
        evidenceProp.addProperty("description",
                "Evidence description (for add/note): what was observed, payload used, response特征");
        props.add("evidence", evidenceProp);

        // level (for add/update)
        JsonObject levelProp = new JsonObject();
        levelProp.addProperty("type", "string");
        levelProp.addProperty("description",
                "Confidence level: CONFIRMED, SUSPECTED, NEGATIVE, NOTE");
        props.add("level", levelProp);

        // finding_id (for update)
        JsonObject idProp = new JsonObject();
        idProp.addProperty("type", "string");
        idProp.addProperty("description",
                "Finding ID to update (for update action, e.g. 'F001')");
        props.add("finding_id", idProp);

        schema.add("properties", props);
        schema.add("required", JsonParser.parseString("[\"action\"]"));
        return schema;
    }

    @Override
    public String execute(String argumentsJson) {
        JsonObject args = JsonParser.parseString(argumentsJson).getAsJsonObject();
        String action = getStr(args, "action");

        if (action == null) {
            return errorJson("action is required: 'add', 'update', or 'note'");
        }

        return switch (action) {
            case "add" -> handleAdd(args);
            case "update" -> handleUpdate(args);
            case "note" -> handleNote(args);
            case "progress" -> handleProgress(args);
            case "checkpoint" -> handleCheckpoint(args);
            default -> errorJson("Unknown action: " + action
                    + ". Use: add, update, note, progress, checkpoint");
        };
    }

    private String handleAdd(JsonObject args) {
        String category = getStr(args, "category");
        String parameter = getStr(args, "parameter");
        String evidence = getStr(args, "evidence");
        String level = getStr(args, "level");

        if (evidence == null || evidence.isEmpty()) {
            return errorJson("evidence is required for 'add' action");
        }
        if (parameter == null) parameter = "unspecified";
        if (category == null) category = "OTHER";
        if (level == null) level = "NOTE";

        String id = findingStore.addManualFinding(category, parameter, evidence, level);

        JsonObject out = new JsonObject();
        out.addProperty("success", true);
        out.addProperty("action", "add");
        out.addProperty("finding_id", id);
        out.addProperty("message", String.format("Finding %s recorded: [%s] %s @ %s",
                id, level, category, parameter));
        out.addProperty("total_findings", findingStore.size());
        return out.toString();
    }

    private String handleUpdate(JsonObject args) {
        String findingId = getStr(args, "finding_id");
        String level = getStr(args, "level");

        if (findingId == null) {
            return errorJson("finding_id is required for 'update' action");
        }
        if (level == null) {
            return errorJson("level is required for 'update' action");
        }

        boolean updated = findingStore.updateFindingLevel(findingId, level);

        JsonObject out = new JsonObject();
        out.addProperty("success", updated);
        out.addProperty("action", "update");
        if (updated) {
            out.addProperty("message", String.format("Finding %s updated to %s", findingId, level));
        } else {
            out.addProperty("message", "Finding " + findingId + " not found");
        }
        return out.toString();
    }

    private String handleNote(JsonObject args) {
        String category = getStr(args, "category");
        String evidence = getStr(args, "evidence");

        if (evidence == null || evidence.isEmpty()) {
            return errorJson("evidence is required for 'note' action");
        }
        if (category == null) category = "OTHER";

        String id = findingStore.addManualFinding(category, "general-note", evidence, "NOTE");

        JsonObject out = new JsonObject();
        out.addProperty("success", true);
        out.addProperty("action", "note");
        out.addProperty("finding_id", id);
        out.addProperty("message", "Note recorded: " + id);
        out.addProperty("total_findings", findingStore.size());
        return out.toString();
    }

    private String handleProgress(JsonObject args) {
        String text = getStr(args, "text");
        if (text == null || text.isEmpty()) {
            // Fall back to evidence field if a model uses the wrong key.
            text = getStr(args, "evidence");
        }
        if (text == null || text.isEmpty()) {
            return errorJson("text is required for 'progress' action "
                    + "(free-text: hypothesis / blockers / failed payloads / endpoints tested)");
        }
        findingStore.appendProgress(text);
        JsonObject out = new JsonObject();
        out.addProperty("success", true);
        out.addProperty("action", "progress");
        out.addProperty("window", findingStore.getCurrentWindowId());
        out.addProperty("message", "Progress recorded for the current window.");
        return out.toString();
    }

    private String handleCheckpoint(JsonObject args) {
        String text = getStr(args, "text");
        if (text == null || text.isEmpty()) {
            text = getStr(args, "evidence");
        }
        if (text == null || text.isEmpty()) {
            return errorJson("text is required for 'checkpoint' action");
        }
        findingStore.appendProgress("[checkpoint] " + text);
        JsonObject out = new JsonObject();
        out.addProperty("success", true);
        out.addProperty("action", "checkpoint");
        out.addProperty("window", findingStore.getCurrentWindowId());
        out.addProperty("message", "Checkpoint recorded.");
        return out.toString();
    }

    private String getStr(JsonObject obj, String key) {
        return obj.has(key) && !obj.get(key).isJsonNull() ? obj.get(key).getAsString() : null;
    }

    private String errorJson(String msg) {
        JsonObject out = new JsonObject();
        out.addProperty("success", false);
        out.addProperty("error", msg);
        return out.toString();
    }
}
