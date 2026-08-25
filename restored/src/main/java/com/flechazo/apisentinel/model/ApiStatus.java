package com.flechazo.apisentinel.model;

import burp.api.montoya.core.HighlightColor;

public enum ApiStatus {
    UNTESTED("未测试", HighlightColor.NONE),
    UNDER_TEST("接口测试中", HighlightColor.YELLOW),
    PENDING_REVIEW("待评估", HighlightColor.CYAN),
    PASSED("测试通过，安全", HighlightColor.GREEN),
    VULNERABLE("存在漏洞", HighlightColor.RED);

    private final String displayName;
    private final HighlightColor highlightColor;

    ApiStatus(String displayName, HighlightColor highlightColor) {
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
