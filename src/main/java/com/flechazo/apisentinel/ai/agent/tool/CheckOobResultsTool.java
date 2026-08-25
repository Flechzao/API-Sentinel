package com.flechazo.apisentinel.ai.agent.tool;

import com.flechazo.apisentinel.detection.OobService;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

import java.util.List;

public class CheckOobResultsTool implements AgentTool {

    private final ToolContext ctx;

    public CheckOobResultsTool(ToolContext ctx) {
        this.ctx = ctx;
    }

    @Override
    public String name() { return "check_oob_results"; }

    @Override
    public String description() {
        return "Poll the OOB callback platform (Burp Collaborator) for interactions triggered by "
             + "previously-generated probes. Returns hits (DNS/HTTP callbacks) confirming blind "
             + "SSRF/XXE/RCE. Call this AFTER sending requests containing OOB probes. "
             + "Optional wait_seconds (default 5, max 30) gives target time to resolve the probe. "
             + "Only works with Collaborator mode (Burp Pro); internal dnslog requires manual check.";
    }

    @Override
    public JsonObject inputSchema() {
        JsonObject schema = new JsonObject();
        schema.addProperty("type", "object");
        JsonObject props = new JsonObject();
        JsonObject waitProp = new JsonObject();
        waitProp.addProperty("type", "integer");
        waitProp.addProperty("description", "Seconds to wait before polling (default 5, max 30)");
        props.add("wait_seconds", waitProp);
        schema.add("properties", props);
        return schema;
    }

    @Override
    public String execute(String argumentsJson) {
        OobService oob = ctx.oobService();
        JsonObject result = new JsonObject();

        if (oob == null || !oob.isEnabled()) {
            result.addProperty("error", "OOB detection is not enabled");
            return result.toString();
        }

        if (!oob.isCollaboratorMode()) {
            result.addProperty("mode", "internal");
            result.addProperty("hits_count", 0);
            result.add("hits", new JsonArray());
            result.addProperty("pending_probes", oob.getPendingProbeCount());
            result.addProperty("hint", "Internal dnslog mode has no polling API. "
                    + "Check the platform manually for interactions.");
            return result.toString();
        }

        int waitSeconds = 5;
        try {
            var args = com.google.gson.JsonParser.parseString(argumentsJson).getAsJsonObject();
            if (args.has("wait_seconds")) {
                waitSeconds = Math.max(1, Math.min(args.get("wait_seconds").getAsInt(), 30));
            }
        } catch (Exception ignored) {}

        try {
            Thread.sleep(waitSeconds * 1000L);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }

        List<OobService.OobInteractionHit> hits = oob.pollInteractions();

        result.addProperty("mode", "collaborator");
        result.addProperty("pending_probes", oob.getPendingProbeCount());

        JsonArray hitsArray = new JsonArray();
        for (OobService.OobInteractionHit hit : hits) {
            JsonObject h = new JsonObject();
            h.addProperty("interaction_type", hit.interactionType());
            h.addProperty("entry_path", hit.probe().entryPath());
            h.addProperty("parameter", hit.probe().parameter());
            h.addProperty("vuln_type", hit.probe().vulnType());
            h.addProperty("probe_hostname", hit.probe().fullHostname());
            hitsArray.add(h);
        }
        result.add("hits", hitsArray);
        result.addProperty("hits_count", hits.size());

        if (!hits.isEmpty()) {
            result.addProperty("hint", hits.size() + " probe(s) received callbacks — "
                    + "this CONFIRMS blind " + hits.get(0).probe().vulnType()
                    + ". Include in confirmed_vulns with this evidence.");
        } else {
            result.addProperty("hint", "No callbacks yet. Target may not be able to reach "
                    + "the collaborator (network isolation/WAF), or the parameter is not vulnerable.");
        }

        return result.toString();
    }
}
