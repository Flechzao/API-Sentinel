package com.flechazo.apisentinel.ai.provider;

import com.google.gson.JsonObject;

public record ToolDefinition(
    String name,
    String description,
    JsonObject inputSchema
) {}
