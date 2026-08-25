package com.flechazo.apisentinel.testgen.model;

import java.util.Map;

public record TestCase(
    String name,
    String category,
    String targetParam,
    String payload,
    String method,
    String path,
    Map<String, String> headers,
    String body,
    String description,
    String expectedIfVulnerable,
    String riskIfConfirmed
) {}
