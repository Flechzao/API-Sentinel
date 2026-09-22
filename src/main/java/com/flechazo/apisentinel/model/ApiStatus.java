package com.flechazo.apisentinel.model;

import burp.api.montoya.core.HighlightColor;

public enum ApiStatus {
    UNTESTED("status_untested", HighlightColor.NONE),
    UNDER_TEST("status_under_test", HighlightColor.YELLOW),
    PENDING_REVIEW("status_pending", HighlightColor.CYAN),
    PASSED("status_passed", HighlightColor.GREEN),
    VULNERABLE("status_vulnerable", HighlightColor.RED);

    private final String i18nKey;
    private final HighlightColor highlightColor;

    ApiStatus(String i18nKey, HighlightColor highlightColor) {
        this.i18nKey = i18nKey;
        this.highlightColor = highlightColor;
    }

    public String getDisplayName() {
        return com.flechazo.apisentinel.ui.I18n.get(i18nKey);
    }

    /** Reverse-lookup: find the ApiStatus whose display name matches. */
    public static ApiStatus fromDisplayName(String displayName) {
        for (ApiStatus s : values()) {
            if (s.getDisplayName().equals(displayName) || s.name().equalsIgnoreCase(displayName)) return s;
        }
        return null;
    }

    public HighlightColor getHighlightColor() {
        return highlightColor;
    }
}
