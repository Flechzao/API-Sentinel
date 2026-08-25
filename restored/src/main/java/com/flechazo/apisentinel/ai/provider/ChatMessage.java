package com.flechazo.apisentinel.ai.provider;

import java.util.List;

public record ChatMessage(
    String role,
    String content,
    String toolCallId,
    List<ToolCall> toolCalls,
    String rawThinkingBlocksJson
) {
    public ChatMessage(String role, String content) {
        this(role, content, null, null, null);
    }

    public ChatMessage(String role, String content, String toolCallId, List<ToolCall> toolCalls) {
        this(role, content, toolCallId, toolCalls, null);
    }

    public static ChatMessage system(String content) {
        return new ChatMessage("system", content);
    }

    public static ChatMessage user(String content) {
        return new ChatMessage("user", content);
    }

    public static ChatMessage assistant(String content) {
        return new ChatMessage("assistant", content);
    }

    public static ChatMessage assistantWithToolCalls(String content, List<ToolCall> toolCalls) {
        return new ChatMessage("assistant", content, null, toolCalls, null);
    }

    /** Same as {@link #assistantWithToolCalls(String, List)} but also carries the
     *  raw thinking/redacted_thinking content blocks (as a serialized JSON array,
     *  provider-opaque) so a provider that requires them echoed back verbatim on
     *  the next multi-turn request (Anthropic extended thinking + tool use) can
     *  do so. Null when the response didn't include any thinking blocks. */
    public static ChatMessage assistantWithToolCalls(String content, List<ToolCall> toolCalls,
                                                       String rawThinkingBlocksJson) {
        return new ChatMessage("assistant", content, null, toolCalls, rawThinkingBlocksJson);
    }

    public static ChatMessage toolResult(String toolCallId, String content) {
        return new ChatMessage("tool", content, toolCallId, null, null);
    }

    public boolean hasToolCalls() {
        return toolCalls != null && !toolCalls.isEmpty();
    }
}
