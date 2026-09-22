package com.flechazo.apisentinel.ai.agent.tool;

import com.flechazo.apisentinel.ai.provider.ToolDefinition;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public class AgentToolRegistry {

    private final Map<String, AgentTool> tools = new LinkedHashMap<>();
    private final ToolContext toolContext;

    public AgentToolRegistry(ToolContext toolContext) {
        this.toolContext = toolContext;
    }

    public void register(AgentTool tool) {
        tools.put(tool.name(), tool);
    }

    public List<ToolDefinition> getDefinitions() {
        return tools.values().stream()
                .map(AgentTool::toDefinition)
                .toList();
    }

    /**
     * Execute a tool with the pre→execute→post pipeline.
     * If preExecute returns a non-null rejection reason, the tool is NOT executed
     * and the rejection text is returned as the result (postExecute is still called).
     */
    public String executeTool(String name, String argsJson) {
        AgentTool tool = tools.get(name);
        if (tool == null) {
            return "{\"error\": \"Unknown tool: " + name + "\"}";
        }
        try {
            // Phase 1: pre-execute gate
            String rejection = tool.preExecute(argsJson, toolContext);
            if (rejection != null) {
                // Call postExecute even on rejection so tools can clean up / log
                tool.postExecute(argsJson, rejection, toolContext);
                return rejection;
            }

            // Phase 2: execute
            String result = tool.execute(argsJson);

            // Phase 3: post-execute processing
            tool.postExecute(argsJson, result, toolContext);

            return result;
        } catch (Exception e) {
            String errorResult = "{\"error\": \"Tool execution failed: " + escapeJson(e.getMessage()) + "\"}";
            try {
                tool.postExecute(argsJson, errorResult, toolContext);
            } catch (Exception ignored) {}
            return errorResult;
        }
    }

    public boolean hasTool(String name) {
        return tools.containsKey(name);
    }

    public AgentTool getTool(String name) {
        return tools.get(name);
    }

    /** Unregister a tool by name (used by tool management to disable tools). */
    public void unregister(String name) {
        tools.remove(name);
    }

    /** Get all registered tool names. */
    public java.util.Set<String> getToolNames() {
        return java.util.Collections.unmodifiableSet(tools.keySet());
    }

    private static String escapeJson(String s) {
        if (s == null) return "";
        StringBuilder sb = new StringBuilder(s.length() + 16);
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '\\' -> sb.append("\\\\");
                case '"' -> sb.append("\\\"");
                case '\n' -> sb.append("\\n");
                case '\r' -> sb.append("\\r");
                case '\t' -> sb.append("\\t");
                case '\b' -> sb.append("\\b");
                case '\f' -> sb.append("\\f");
                default -> {
                    // Strip other C0 control chars (< 0x20) that would produce
                    // malformed JSON and derail the LLM's parsing of tool output.
                    if (c < 0x20) {
                        sb.append(' ');
                    } else {
                        sb.append(c);
                    }
                }
            }
        }
        return sb.toString();
    }
}
