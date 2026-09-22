package com.flechazo.apisentinel.config;

public enum MatchMode {
    EXACT("match_exact_mode", "精确匹配", "Exact"),
    FUZZY("match_fuzzy_mode", "模糊匹配", "Fuzzy");

    private final String i18nKey;
    private final String zh;
    private final String en;

    MatchMode(String i18nKey, String zh, String en) {
        this.i18nKey = i18nKey;
        this.zh = zh;
        this.en = en;
    }

    public String getDisplayName() {
        try {
            return com.flechazo.apisentinel.ui.I18n.get(i18nKey);
        } catch (Exception e) {
            return zh;
        }
    }

    public MatchMode normalize() {
        return switch (this) {
            case EXACT -> EXACT;
            case FUZZY -> FUZZY;
        };
    }
}
