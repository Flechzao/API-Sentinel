package com.flechazo.apisentinel.config;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for F-1 browser configuration fields in AppConfig.
 */
class AppConfigBrowserTest {

    @Test
    void defaults_browserDisabled() {
        AppConfig config = new AppConfig();
        assertFalse(config.isBrowserEnabled());
        assertTrue(config.isBrowserHeadless()); // headless by default
        assertEquals("", config.getBrowserChromePath());
        assertEquals(10, config.getBrowserMaxPages());
    }

    @Test
    void setBrowserEnabled_togglesFlag() {
        AppConfig config = new AppConfig();
        config.setBrowserEnabled(true);
        assertTrue(config.isBrowserEnabled());
        config.setBrowserEnabled(false);
        assertFalse(config.isBrowserEnabled());
    }

    @Test
    void setBrowserHeadless_togglesFlag() {
        AppConfig config = new AppConfig();
        config.setBrowserHeadless(false);
        assertFalse(config.isBrowserHeadless());
    }

    @Test
    void setBrowserChromePath_handlesNull() {
        AppConfig config = new AppConfig();
        config.setBrowserChromePath(null);
        assertEquals("", config.getBrowserChromePath());

        config.setBrowserChromePath("/usr/bin/chrome");
        assertEquals("/usr/bin/chrome", config.getBrowserChromePath());
    }

    @Test
    void setBrowserMaxPages_clamps() {
        AppConfig config = new AppConfig();

        // Below minimum (1)
        config.setBrowserMaxPages(0);
        assertEquals(1, config.getBrowserMaxPages());

        // Above maximum (50)
        config.setBrowserMaxPages(100);
        assertEquals(50, config.getBrowserMaxPages());

        // Normal value
        config.setBrowserMaxPages(20);
        assertEquals(20, config.getBrowserMaxPages());
    }
}
