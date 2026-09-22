package com.flechazo.apisentinel.config;

import com.flechazo.apisentinel.config.LoginProfile.LoginStrategy;
import com.google.gson.JsonObject;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for {@link LoginProfile} serialization, deserialization, and helper methods.
 */
class LoginProfileTest {

    @Test
    void testSimpleFactory() {
        LoginProfile profile = LoginProfile.simple("test", "https://app.example.com/login", "user", "pass");

        assertEquals("test", profile.name());
        assertEquals("https://app.example.com/login", profile.loginUrl());
        assertEquals("user", profile.username());
        assertEquals("pass", profile.password());
        assertEquals(LoginStrategy.AUTO, profile.strategy());
        assertTrue(profile.persistCookies());
        // formSelectors may be empty for AUTO strategy
        assertNotNull(profile.formSelectors());
    }

    @Test
    void testJsonRoundTrip() {
        LoginProfile original = new LoginProfile(
                "生产环境",
                "https://app.prod.example.com/login",
                "admin",
                "secret123",
                LoginStrategy.CUSTOM_FORM,
                Map.of("username", "#login-user", "password", "#login-pwd", "submit", ".btn-login"),
                List.of("/dashboard", "/admin"),
                true
        );

        JsonObject json = original.toJson();
        LoginProfile parsed = LoginProfile.fromJson(json);

        assertEquals(original.name(), parsed.name());
        assertEquals(original.loginUrl(), parsed.loginUrl());
        assertEquals(original.username(), parsed.username());
        assertEquals(original.password(), parsed.password());
        assertEquals(original.strategy(), parsed.strategy());
        assertEquals(original.formSelectors(), parsed.formSelectors());
        assertEquals(original.successIndicators(), parsed.successIndicators());
        assertEquals(original.persistCookies(), parsed.persistCookies());
    }

    @Test
    void testDefaultSelectors() {
        LoginProfile profile = LoginProfile.simple("test", "https://example.com/login", "u", "p");

        // Should return default selectors when formSelectors is empty
        assertNotNull(profile.getUsernameSelector());
        assertNotNull(profile.getPasswordSelector());
        assertNotNull(profile.getSubmitSelector());
        assertTrue(profile.getPasswordSelector().contains("password"));
    }

    @Test
    void testCustomSelectors() {
        LoginProfile profile = new LoginProfile(
                "test", "https://example.com/login", "u", "p",
                LoginStrategy.CUSTOM_FORM,
                Map.of("username", "#my-user", "password", "#my-pwd", "submit", "#my-submit"),
                List.of(), true
        );

        assertEquals("#my-user", profile.getUsernameSelector());
        assertEquals("#my-pwd", profile.getPasswordSelector());
        assertEquals("#my-submit", profile.getSubmitSelector());
    }

    @Test
    void testIsSuccessUrl() {
        LoginProfile profile = new LoginProfile(
                "test", "https://example.com/login", "u", "p",
                LoginStrategy.AUTO,
                Map.of(),
                List.of("/dashboard", "/home"),
                true
        );

        assertTrue(profile.isSuccessUrl("https://example.com/dashboard"));
        assertTrue(profile.isSuccessUrl("https://example.com/home"));
        assertFalse(profile.isSuccessUrl("https://example.com/login"));
        assertFalse(profile.isSuccessUrl("https://example.com/sso/auth"));
    }

    @Test
    void testFromJsonDefaults() {
        // Minimal JSON should use defaults
        JsonObject json = new JsonObject();
        json.addProperty("name", "minimal");
        json.addProperty("loginUrl", "https://example.com/login");

        LoginProfile profile = LoginProfile.fromJson(json);

        assertEquals("minimal", profile.name());
        assertEquals(LoginStrategy.AUTO, profile.strategy());
        assertTrue(profile.persistCookies()); // default true
        assertFalse(profile.successIndicators().isEmpty()); // has defaults
    }
}
