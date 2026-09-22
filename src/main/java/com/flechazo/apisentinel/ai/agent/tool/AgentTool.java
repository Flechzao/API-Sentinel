package com.flechazo.apisentinel.ai.agent.tool;

import com.flechazo.apisentinel.ai.provider.ToolDefinition;
import com.google.gson.JsonObject;

public interface AgentTool {

    String name();

    String description();

    JsonObject inputSchema();

    /**
     * Execute the tool.
     */
    String execute(String argumentsJson);

    /**
     * Whether this tool is side-effect-free and reads only shared session state,
     * making it safe to run concurrently with other read-only tools returned in the
     * same LLM response. Tools that send a request, call an LLM, or mutate
     * cross-tool state (send_request, generate_payloads, submit_report, chain_hunter,
     * verify_*, …) must return {@code false} so they always run sequentially in
     * submission order.
     * <p>Default {@code false} is the safe choice: a newly added tool never silently
     * parallelises until it opts in here.
     */
    default boolean isReadOnly() {
        return false;
    }

    /**
     * Pre-execution hook: gate checks, permission validation, state inspection.
     * Called before {@link #execute} on every tool invocation.
     *
     * @param argumentsJson the tool call arguments as a JSON string
     * @param ctx the tool context (shared across all tools in this analysis)
     * @return null to allow execution; a non-null string to reject with a reason
     */
    default String preExecute(String argumentsJson, ToolContext ctx) {
        return null; // allow by default
    }

    /**
     * Post-execution hook: result processing, triggering follow-up actions,
     * UI updates. Called after {@link #execute} regardless of success/failure.
     *
     * @param argumentsJson the original tool call arguments
     * @param result the raw result string from {@link #execute} (may be an error JSON)
     * @param ctx the tool context
     */
    default void postExecute(String argumentsJson, String result, ToolContext ctx) {
        // no-op by default
    }

    default ToolDefinition toDefinition() {
        return new ToolDefinition(name(), description(), inputSchema());
    }
}
