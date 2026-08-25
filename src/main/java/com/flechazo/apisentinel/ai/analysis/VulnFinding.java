package com.flechazo.apisentinel.ai.analysis;

public record VulnFinding(
    String type,
    String risk,
    double confidence,
    String title,
    String description,
    String evidence,
    String location,
    String remediation
) {}
