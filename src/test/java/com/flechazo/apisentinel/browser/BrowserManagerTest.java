package com.flechazo.apisentinel.browser;

import com.flechazo.apisentinel.logging.LeveledLogger;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests for BrowserManager lifecycle management.
 * Note: These tests do NOT actually launch a browser (would require Playwright runtime).
 * They verify configuration and state management only.
 */
class BrowserManagerTest {

    private BrowserManager manager;

    @BeforeEach
    void setUp() {
        // Use a null-safe logger wrapper for tests
        manager = new BrowserManager(new LeveledLogger(null));
    }

    @AfterEach
    void tearDown() {
        manager.close();
    }

    @Test
    void shouldNotBeRunningInitially() {
        assertThat(manager.isRunning()).isFalse();
    }

    @Test
    void configure_shouldStoreSettings() {
        manager.configure(9999, false, "/usr/bin/chromium");

        assertThat(manager.getBurpProxyPort()).isEqualTo(9999);
    }

    @Test
    void close_shouldBeIdempotent() {
        // Calling close on a non-running manager should not throw
        manager.close();
        manager.close();

        assertThat(manager.isRunning()).isFalse();
    }

    @Test
    void defaultProxyPort_shouldBe8080() {
        assertThat(manager.getBurpProxyPort()).isEqualTo(8080);
    }
}
