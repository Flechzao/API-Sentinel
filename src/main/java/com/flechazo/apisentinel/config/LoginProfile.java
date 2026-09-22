package com.flechazo.apisentinel.config;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.*;

/**
 * Represents a login configuration for a specific application/environment.
 *
 * <p>Each profile contains the information needed to automatically log in
 * to a web application: URL, credentials, form selectors, and success indicators.
 *
 * <p>Profiles are persisted to {@code ~/.api-sentinel/login-profiles.json}.
 *
 * @param name              profile name (e.g., "生产环境", "测试环境")
 * @param loginUrl          the login page URL
 * @param username          username for login
 * @param password          password (stored encrypted if possible)
 * @param strategy          login strategy: AUTO, CUSTOM_FORM, or SSO_BUC
 * @param formSelectors     custom CSS selectors for form elements (optional)
 * @param successIndicators URL patterns or element selectors that indicate login success
 * @param persistCookies    whether to persist cookies to disk after login
 */
public record LoginProfile(
        String name,
        String loginUrl,
        String username,
        String password,
        LoginStrategy strategy,
        Map<String, String> formSelectors,
        List<String> successIndicators,
        boolean persistCookies
) {

    /**
     * Login strategy options.
     */
    public enum LoginStrategy {
        /** Automatically detect login form elements. */
        AUTO,
        /** Use custom CSS selectors from formSelectors map. */
        CUSTOM_FORM,
        /** Handle SSO/BUC redirect flow specially. */
        SSO_BUC
    }

    /**
     * Form selector keys for CUSTOM_FORM strategy.
     */
    public static final String SELECTOR_USERNAME = "username";
    public static final String SELECTOR_PASSWORD = "password";
    public static final String SELECTOR_SUBMIT = "submit";

    /**
     * Creates a profile with AUTO strategy and default settings.
     */
    public static LoginProfile simple(String name, String loginUrl, String username, String password) {
        return new LoginProfile(
                name, loginUrl, username, password,
                LoginStrategy.AUTO,
                Map.of(),
                List.of("/dashboard", "/home", "/index"),
                true
        );
    }

    /**
     * Get the selector for the username input field.
     *
     * @return the selector, or a default if not specified
     */
    public String getUsernameSelector() {
        return formSelectors.getOrDefault(SELECTOR_USERNAME,
                "input[type=text][name*=user], input[type=text][name*=account], input[type=email], #username, #loginName");
    }

    /**
     * Get the selector for the password input field.
     *
     * @return the selector, or a default if not specified
     */
    public String getPasswordSelector() {
        return formSelectors.getOrDefault(SELECTOR_PASSWORD,
                "input[type=password]");
    }

    /**
     * Get the selector for the submit button.
     *
     * @return the selector, or a default if not specified
     */
    public String getSubmitSelector() {
        return formSelectors.getOrDefault(SELECTOR_SUBMIT,
                "button[type=submit], input[type=submit], .login-btn, .submit-btn, button:has-text('登录'), button:has-text('Login')");
    }

    /**
     * Check if a URL matches any success indicator.
     *
     * @param currentUrl the current page URL
     * @return true if the URL indicates login success
     */
    public boolean isSuccessUrl(String currentUrl) {
        if (currentUrl == null || currentUrl.isEmpty()) return false;
        for (String indicator : successIndicators) {
            if (currentUrl.contains(indicator)) {
                return true;
            }
        }
        // Also check if we're no longer on a login page
        return !currentUrl.contains("/login") && !currentUrl.contains("/sso")
                && !currentUrl.contains("/auth") && !currentUrl.contains("/signin");
    }

    /**
     * Convert this profile to JSON for persistence.
     */
    public JsonObject toJson() {
        JsonObject obj = new JsonObject();
        obj.addProperty("name", name);
        obj.addProperty("loginUrl", loginUrl);
        obj.addProperty("username", username);
        obj.addProperty("password", password);
        obj.addProperty("strategy", strategy.name());
        obj.addProperty("persistCookies", persistCookies);

        if (!formSelectors.isEmpty()) {
            JsonObject selectors = new JsonObject();
            formSelectors.forEach(selectors::addProperty);
            obj.add("formSelectors", selectors);
        }

        if (!successIndicators.isEmpty()) {
            JsonArray indicators = new JsonArray();
            successIndicators.forEach(indicators::add);
            obj.add("successIndicators", indicators);
        }

        return obj;
    }

    /**
     * Parse a profile from JSON.
     */
    public static LoginProfile fromJson(JsonObject obj) {
        String name = obj.has("name") ? obj.get("name").getAsString() : "default";
        String loginUrl = obj.has("loginUrl") ? obj.get("loginUrl").getAsString() : "";
        String username = obj.has("username") ? obj.get("username").getAsString() : "";
        String password = obj.has("password") ? obj.get("password").getAsString() : "";

        LoginStrategy strategy = LoginStrategy.AUTO;
        if (obj.has("strategy")) {
            try {
                strategy = LoginStrategy.valueOf(obj.get("strategy").getAsString());
            } catch (IllegalArgumentException ignored) {}
        }

        Map<String, String> formSelectors = new LinkedHashMap<>();
        if (obj.has("formSelectors")) {
            JsonObject selectors = obj.getAsJsonObject("formSelectors");
            for (String key : selectors.keySet()) {
                formSelectors.put(key, selectors.get(key).getAsString());
            }
        }

        List<String> successIndicators = new ArrayList<>();
        if (obj.has("successIndicators")) {
            JsonArray indicators = obj.getAsJsonArray("successIndicators");
            for (JsonElement el : indicators) {
                successIndicators.add(el.getAsString());
            }
        }
        if (successIndicators.isEmpty()) {
            successIndicators = new ArrayList<>(List.of("/dashboard", "/home", "/index"));
        }

        boolean persistCookies = !obj.has("persistCookies") || obj.get("persistCookies").getAsBoolean();

        return new LoginProfile(name, loginUrl, username, password, strategy,
                formSelectors, successIndicators, persistCookies);
    }
}
