package com.flechazo.apisentinel.ai.provider;

import java.util.List;

public record ChatMessage(
    String role,
    String content,
    String toolCallId,
    List<ToolCall> toolCalls,
    String rawThinkingBlocksJson,
    /** Base64-encoded image data (PNG/JPEG) for vision models. Null if no image. */
    String imageBase64,
    /** MIME type of the image (e.g., "image/png"). Null if no image. */
    String imageMimeType
) {
    public ChatMessage(String role, String content) {
        this(role, content, null, null, null, null, null);
    }

    public ChatMessage(String role, String content, String toolCallId, List<ToolCall> toolCalls) {
        this(role, content, toolCallId, toolCalls, null, null, null);
    }

    public ChatMessage(String role, String content, String toolCallId, List<ToolCall> toolCalls,
                       String rawThinkingBlocksJson) {
        this(role, content, toolCallId, toolCalls, rawThinkingBlocksJson, null, null);
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
        return new ChatMessage("tool", content, toolCallId, null, null, null, null);
    }

    /**
     * Create a user message with an image (for vision models).
     *
     * @param content    text prompt to accompany the image
     * @param imageBase64 base64-encoded image data
     * @param mimeType   MIME type (e.g., "image/png", "image/jpeg")
     */
    public static ChatMessage userWithImage(String content, String imageBase64, String mimeType) {
        return new ChatMessage("user", content, null, null, null, imageBase64, mimeType);
    }

    /** Check if this message contains an image. */
    public boolean hasImage() {
        return imageBase64 != null && !imageBase64.isEmpty();
    }

    public boolean hasToolCalls() {
        return toolCalls != null && !toolCalls.isEmpty();
    }
}
