package com.flechazo.apisentinel.ui;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class I18nTest {

    @Test
    void zhKeys_returnChinese() {
        I18n.setLang(I18n.Lang.ZH);
        assertEquals("导入 API", I18n.get("import_api"));
        assertEquals("代码仓库管理", I18n.get("repo_mgmt"));
        assertEquals("添加仓库", I18n.get("repo_add"));
    }

    @Test
    void enKeys_returnEnglish() {
        I18n.setLang(I18n.Lang.EN);
        assertEquals("Import API", I18n.get("import_api"));
        assertEquals("Code Repository Management", I18n.get("repo_mgmt"));
        assertEquals("Add Repo", I18n.get("repo_add"));
        I18n.setLang(I18n.Lang.ZH);
    }

    @Test
    void unknownKey_returnsKeyItself() {
        assertEquals("nonexistent_key_xyz", I18n.get("nonexistent_key_xyz"));
    }

    @Test
    void toggle_switchesLanguage() {
        I18n.setLang(I18n.Lang.ZH);
        I18n.toggle();
        assertEquals(I18n.Lang.EN, I18n.getLang());
        I18n.toggle();
        assertEquals(I18n.Lang.ZH, I18n.getLang());
    }

    @Test
    void newKeys_exist() {
        I18n.setLang(I18n.Lang.ZH);
        assertNotEquals("rules_title", I18n.get("rules_title"));
        assertNotEquals("ctx_ai_analyze", I18n.get("ctx_ai_analyze"));
        assertNotEquals("analysis_mode_traffic", I18n.get("analysis_mode_traffic"));
        assertNotEquals("dash_total_api", I18n.get("dash_total_api"));
        assertNotEquals("dash_cascade_off", I18n.get("dash_cascade_off"));
        assertNotEquals("toast_high_risk", I18n.get("toast_high_risk"));
    }
}
