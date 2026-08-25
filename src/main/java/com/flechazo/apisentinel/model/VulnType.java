package com.flechazo.apisentinel.model;

import burp.api.montoya.core.HighlightColor;

public enum VulnType {
    GENERIC("存在漏洞", HighlightColor.RED),
    UNAUTHORIZED("未授权", HighlightColor.ORANGE),
    HORIZONTAL_PRIV_ESC("水平越权", HighlightColor.ORANGE),
    VERTICAL_PRIV_ESC("垂直越权", HighlightColor.ORANGE),
    SENSITIVE_INFO("敏感信息泄露", HighlightColor.ORANGE);

    private final String displayName;
    private final HighlightColor highlightColor;

    VulnType(String displayName, HighlightColor highlightColor) {
        this.displayName = displayName;
        this.highlightColor = highlightColor;
    }

    public String getDisplayName() {
        return displayName;
    }

    public HighlightColor getHighlightColor() {
        return highlightColor;
    }
}
