package com.flechazo.apisentinel.ai.agent.tool;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

/**
 * Agent tool for updating individual security findings during chat follow-up.
 *
 * <p>Allows the Agent to promote a "suspected" finding to "confirmed" after
 * additional verification via send_request, or dismiss a false positive.
 * This is a lightweight alternative to re-running submit_report for the
 * entire verdict.
 *
 * <p>Use when: the user asks to verify a specific suspected vulnerability,
 * and the Agent has gathered enough evidence via send_request to confirm it.
 */
public class UpdateFindingTool implements AgentTool {

    private final ToolContext ctx;

    public UpdateFindingTool(ToolContext ctx) {
        this.ctx = ctx;
    }

    @Override
    public String name() { return "update_finding"; }

    @Override
    public String description() {
        return "Update the status of a single security finding (promote suspected→confirmed, "
             + "or dismiss a false positive). Use after verifying a suspected vulnerability "
             + "with send_request and gathering sufficient evidence. "
             + "This updates the findings table immediately without re-running the full analysis. "
             + "Use getFindingSummaries() first to see available findings and their indices.";
    }

    @Override
    public JsonObject inputSchema() {
        JsonObject schema = new JsonObject();
        schema.addProperty("type", "object");

        JsonObject props = new JsonObject();
        props.add("finding_index", prop("integer",
                "0-based index of the finding to update. "
                + "Call with finding_index=-1 first to list all available findings."));
        props.add("new_status", prop("string",
                "New status: 'confirmed' (verified with evidence), "
                + "'dismissed' (false positive), or 'suspected' (revert to suspected)."));
        props.add("evidence", prop("string",
                "Updated evidence text describing how the vulnerability was verified. "
                + "Required when new_status is 'confirmed'."));
        props.add("payload_used", prop("string",
                "The HTTP request/payload that verified this finding."));
        props.add("response", prop("string",
                "The response snippet that confirms the vulnerability."));

        schema.add("properties", props);
        schema.add("required", JsonParser.parseString("[\"finding_index\", \"new_status\"]"));
        return schema;
    }

    @Override
    public String execute(String argumentsJson) {
        JsonObject args = JsonParser.parseString(argumentsJson).getAsJsonObject();
        int index = args.has("finding_index") ? args.get("finding_index").getAsInt() : -1;
        String newStatus = getStr(args, "new_status");

        FindingUpdater updater = ctx.findingUpdater();
        if (updater == null) {
            return errorJson("Finding updater not available (only works in chat follow-up mode).");
        }

        // Special: index=-1 lists all findings
        if (index < 0) {
            String[] summaries = updater.getFindingSummaries();
            if (summaries == null || summaries.length == 0) {
                return errorJson("No findings available. Run the full analysis first.");
            }
            JsonObject out = new JsonObject();
            out.addProperty("action", "list");
            JsonArray arr = new JsonArray();
            for (String s : summaries) {
                arr.add(s);
            }
            out.add("findings", arr);
            out.addProperty("count", summaries.length);
            out.addProperty("note", "Use finding_index to update a specific finding.");
            return out.toString();
        }

        // Validate status
        if (newStatus == null || (!"confirmed".equals(newStatus)
                && !"dismissed".equals(newStatus) && !"suspected".equals(newStatus))) {
            return errorJson("new_status must be 'confirmed', 'dismissed', or 'suspected'.");
        }

        // Evidence required for confirmed
        String evidence = getStr(args, "evidence");
        if ("confirmed".equals(newStatus) && (evidence == null || evidence.isBlank())) {
            return errorJson("evidence is required when promoting to 'confirmed'.");
        }

        String payloadUsed = getStr(args, "payload_used");
        String response = getStr(args, "response");

        boolean ok = updater.updateFinding(index, newStatus, evidence, payloadUsed, response);
        if (!ok) {
            String[] summaries = updater.getFindingSummaries();
            int max = summaries != null ? summaries.length : 0;
            return errorJson("Invalid finding_index " + index + ". Valid range: 0-" + (max - 1));
        }

        JsonObject out = new JsonObject();
        out.addProperty("success", true);
        out.addProperty("message", String.format("Finding #%d updated to '%s'", index, newStatus));
        out.addProperty("note", "The findings table has been updated. "
                + "Use finding_index=-1 to verify the current state.");
        return out.toString();
    }

    private JsonObject prop(String type, String desc) {
        JsonObject p = new JsonObject();
        p.addProperty("type", type);
        p.addProperty("description", desc);
        return p;
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
