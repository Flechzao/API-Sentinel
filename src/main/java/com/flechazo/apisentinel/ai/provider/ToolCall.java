package com.flechazo.apisentinel.ai.provider;

public record ToolCall(
    String id,
    String toolName,
    String arguments
) {}
