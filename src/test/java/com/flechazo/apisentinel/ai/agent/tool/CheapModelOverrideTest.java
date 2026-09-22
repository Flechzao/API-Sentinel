package com.flechazo.apisentinel.ai.agent.tool;

import com.flechazo.apisentinel.config.AppConfig;
import com.flechazo.apisentinel.logging.LeveledLogger;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/** Cost-tiering routing decision: only tier down when the switch is on AND a
 *  轻量模型 is configured; otherwise fall back to the main model (null). */
class CheapModelOverrideTest {

    private static ToolContext ctx() {
        return new ToolContext(null, null, null, null, null, null, new LeveledLogger(null));
    }

    @Test
    void tieringOff_returnsNull() {
        AppConfig cfg = new AppConfig();
        cfg.setModelTieringEnabled(false);
        ToolContext c = ctx();
        c.setAppConfig(cfg);
        c.setFastModel("cheap-model");
        assertNull(c.cheapModelOverride(), "tiering off → main model");
    }

    @Test
    void tieringOn_withFastModel_returnsIt() {
        AppConfig cfg = new AppConfig();
        cfg.setModelTieringEnabled(true);
        ToolContext c = ctx();
        c.setAppConfig(cfg);
        c.setFastModel("cheap-model");
        assertEquals("cheap-model", c.cheapModelOverride());
    }

    @Test
    void tieringOn_noFastModel_returnsNull() {
        AppConfig cfg = new AppConfig();
        cfg.setModelTieringEnabled(true);
        ToolContext c = ctx();
        c.setAppConfig(cfg);
        // fastModel unset/blank → nothing to downgrade to
        assertNull(c.cheapModelOverride(), "no 轻量模型 configured → main model");
    }
}
