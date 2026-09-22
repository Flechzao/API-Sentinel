package com.flechazo.apisentinel.ai.agent.tool;

import com.flechazo.apisentinel.ai.agent.ProgressiveToolDisclosure;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

/**
 * Meta-tool that lets the agent request loading of additional tool groups.
 *
 * <p>When the agent's current tool set doesn't include what it needs,
 * it can call {@code request_tools(group)} to load more tools on demand.
 * This implements Progressive Tool Disclosure's "pull" mechanism.
 *
 * <p>Available groups:
 * <ul>
 *   <li>{@code recon} — heuristic_scan, audit_codebase, code search tools</li>
 *   <li>{@code payload_testing} — generate_payloads, verify_* tools</li>
 *   <li>{@code browser} — browser_discover, browser_interact, etc.</li>
 *   <li>{@code advanced} — active_probe, generate_oob_probe, run_sandboxed_code</li>
 *   <li>{@code chain} — chain_hunter, map_sibling_endpoints</li>
 * </ul>
 */
public class RequestToolsTool implements AgentTool {

    private final ProgressiveToolDisclosure disclosure;

    public RequestToolsTool(ProgressiveToolDisclosure disclosure) {
        this.disclosure = disclosure;
    }

    @Override
    public String name() { return "request_tools"; }

    @Override
    public String description() {
        return "Request loading of additional tool groups when your current tool set "
             + "doesn't include what you need. Available groups: "
             + "recon, payload_testing, browser, advanced, chain. "
             + "Example: request_tools(\"payload_testing\") loads generate_payloads and verify_* tools. "
             + "Use when you've identified a vulnerability type but don't have the right tools to test it.";
    }

    @Override
    public JsonObject inputSchema() {
        JsonObject schema = new JsonObject();
        schema.addProperty("type", "object");
        JsonObject props = new JsonObject();

        JsonObject groupProp = new JsonObject();
        groupProp.addProperty("type", "string");
        groupProp.addProperty("description",
                "Tool group to load: recon, payload_testing, browser, advanced, chain");
        props.add("group", groupProp);

        schema.add("properties", props);
        schema.add("required", JsonParser.parseString("[\"group\"]"));
        return schema;
    }

    @Override
    public String execute(String argumentsJson) {
        JsonObject args = JsonParser.parseString(argumentsJson).getAsJsonObject();
        String group = args.has("group") ? args.get("group").getAsString() : "";

        if (group.isEmpty()) {
            return errorJson("group is required. Available: " + disclosure.getAvailableGroupsDescription());
        }

        boolean loaded = disclosure.requestToolGroup(group);
        JsonObject out = new JsonObject();
        out.addProperty("success", loaded);

        if (loaded) {
            out.addProperty("message", "Tool group '" + group + "' loaded. "
                    + "New tools are now available for your next action.");
        } else {
            out.addProperty("message", "Unknown group '" + group + "'. Available groups:\n"
                    + disclosure.getAvailableGroupsDescription());
        }

        return out.toString();
    }

    private String errorJson(String msg) {
        JsonObject out = new JsonObject();
        out.addProperty("success", false);
        out.addProperty("error", msg);
        return out.toString();
    }
}
