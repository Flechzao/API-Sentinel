package com.flechazo.apisentinel.config;

import com.flechazo.apisentinel.config.LoginProfile.LoginStrategy;
import com.flechazo.apisentinel.logging.LeveledLogger;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.mock;

/**
 * Tests for {@link LoginProfileManager} add/remove/find/persist operations.
 */
class LoginProfileManagerTest {

    private LoginProfileManager manager;
    private LeveledLogger logger;

    @TempDir
    Path tempDir;

    @BeforeEach
    void setUp() {
        logger = mock(LeveledLogger.class);
        // Use temp directory to avoid loading user's actual profiles
        manager = new LoginProfileManager(logger, tempDir.resolve("test-profiles.json"));
    }

    @Test
    void testAddAndFind() {
        LoginProfile profile = LoginProfile.simple("test", "https://app.example.com/login", "user", "pass");

        assertTrue(manager.add(profile));
        assertTrue(manager.findByName("test").isPresent());
        assertEquals("test", manager.findByName("test").get().name());
    }

    @Test
    void testAddDuplicate() {
        LoginProfile profile = LoginProfile.simple("test", "https://example.com/login", "u", "p");

        assertTrue(manager.add(profile));
        assertFalse(manager.add(profile)); // duplicate
    }

    @Test
    void testRemove() {
        LoginProfile profile = LoginProfile.simple("test", "https://example.com/login", "u", "p");
        manager.add(profile);

        assertTrue(manager.remove("test"));
        assertFalse(manager.findByName("test").isPresent());
    }

    @Test
    void testFindByUrl() {
        LoginProfile profile = LoginProfile.simple("prod",
                "https://app.example.com/login", "u", "p");
        manager.add(profile);

        // Same domain
        assertTrue(manager.findByUrl("https://app.example.com/dashboard").isPresent());

        // Different domain
        assertFalse(manager.findByUrl("https://other.example.org/login").isPresent());
    }

    @Test
    void testGetDefault() {
        assertTrue(manager.getDefault().isEmpty()); // empty initially

        LoginProfile profile = LoginProfile.simple("first", "https://example.com/login", "u", "p");
        manager.add(profile);

        assertTrue(manager.getDefault().isPresent());
        assertEquals("first", manager.getDefault().get().name());
    }

    @Test
    void testUpdate() {
        LoginProfile original = LoginProfile.simple("test", "https://old.example.com/login", "u", "p");
        manager.add(original);

        LoginProfile updated = new LoginProfile("test", "https://new.example.com/login",
                "new_user", "new_pass", LoginStrategy.SSO_BUC, Map.of(), List.of(), true);

        assertTrue(manager.update(updated));
        assertEquals("https://new.example.com/login", manager.findByName("test").get().loginUrl());
        assertEquals(LoginStrategy.SSO_BUC, manager.findByName("test").get().strategy());
    }

    @Test
    void testGetAll() {
        manager.add(LoginProfile.simple("a", "https://a.example.com/login", "u", "p"));
        manager.add(LoginProfile.simple("b", "https://b.example.com/login", "u", "p"));

        assertEquals(2, manager.getAll().size());
    }
}
