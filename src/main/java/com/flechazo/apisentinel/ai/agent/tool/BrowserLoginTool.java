package com.flechazo.apisentinel.ai.agent.tool;

import com.flechazo.apisentinel.browser.BrowserLogin;
import com.flechazo.apisentinel.browser.BrowserLogin.LoginResult;
import com.flechazo.apisentinel.browser.BrowserManager;
import com.flechazo.apisentinel.config.AppConfig;
import com.flechazo.apisentinel.config.LoginProfile;
import com.flechazo.apisentinel.config.LoginProfileManager;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import java.util.Optional;

/**
 * Agent tool for automatic browser login.
 *
 * <p>Logs into a web application using a configured {@link LoginProfile},
 * captures session cookies, and injects them into the application's auth config.
 *
 * <p>Use when: you need authenticated access to test APIs, or the target page
 * requires login and no cookies have been configured yet.
 *
 * <p>Supports:
 * <ul>
 *   <li>Username/password forms (auto-detected)</li>
 *   <li>Custom form selectors</li>
 *   <li>SSO/BUC redirect flows</li>
 * </ul>
 */
public class BrowserLoginTool implements AgentTool {

    private final ToolContext ctx;
    private final BrowserManager browserManager;
    private final AppConfig appConfig;
    private final LoginProfileManager profileManager;

    public BrowserLoginTool(ToolContext ctx, BrowserManager browserManager,
                            AppConfig appConfig, LoginProfileManager profileManager) {
        this.ctx = ctx;
        this.browserManager = browserManager;
        this.appConfig = appConfig;
        this.profileManager = profileManager;
    }

    @Override
    public String name() { return "browser_login"; }

    @Override
    public String description() {
        return "Login to a web application and capture session cookies. "
             + "Use when: you need authenticated access to test APIs, "
             + "the target page requires login, or auth cookies haven't been configured. "
             + "Supports: username/password forms (auto-detected), custom selectors, SSO/BUC redirects. "
             + "After login, cookies are automatically injected into the auth config "
             + "and can be used by send_request and other tools. "
             + "All browser traffic goes through Burp proxy automatically.";
    }

    @Override
    public JsonObject inputSchema() {
        JsonObject schema = new JsonObject();
        schema.addProperty("type", "object");

        JsonObject props = new JsonObject();
        props.add("profile_name", prop("string",
                "Name of the login profile to use (from configured profiles). "
                + "If omitted, uses the default profile or auto-matches by URL."));
        props.add("login_url", prop("string",
                "Login page URL. Required if no profile is configured."));
        props.add("username", prop("string",
                "Username for login. Required if no profile is configured."));
        props.add("password", prop("string",
                "Password for login. Required if no profile is configured."));
        props.add("strategy", prop("string",
                "Login strategy: 'auto' (default), 'custom_form', or 'sso_buc'. "
                + "Use 'sso_buc' for BUC/SSO redirect flows."));
        props.add("username_selector", prop("string",
                "Custom CSS selector for username input (only with 'custom_form' strategy)."));
        props.add("password_selector", prop("string",
                "Custom CSS selector for password input (only with 'custom_form' strategy)."));
        props.add("submit_selector", prop("string",
                "Custom CSS selector for submit button (only with 'custom_form' strategy)."));
        props.add("remember", prop("boolean",
                "If true, persist this account to ~/.api-sentinel/login-profiles.json under an "
                + "auto-generated name 'auto-<domain>' so future logins to the same domain reuse it "
                + "without asking the user again. Default false. The user can delete the file manually "
                + "to forget the account. Passwords are stored in plaintext; only set remember=true "
                + "when the user has consented (typically after ask_user flow)."));

        schema.add("properties", props);
        schema.add("required", JsonParser.parseString("[]"));
        return schema;
    }

    @Override
    public String execute(String argumentsJson) {
        if (browserManager == null) {
            return errorJson("Browser service not available. Enable browser in settings.");
        }

        JsonObject args = JsonParser.parseString(argumentsJson).getAsJsonObject();

        // Resolve login profile
        LoginProfile profile = resolveProfile(args);
        if (profile == null) {
            return errorJson("No login profile found. Provide login_url, username, and password, "
                    + "or configure a profile in settings. "
                    + "Available profiles: " + listProfileNames());
        }

        // Perform login
        BrowserLogin login = new BrowserLogin(ctx.logger(), browserManager);
        login.setAppConfig(appConfig);

        LoginResult result = login.login(profile);

        // Read the remember flag BEFORE we potentially rewrite `profile`
        boolean remember = args.has("remember")
                && args.get("remember").isJsonPrimitive()
                && args.get("remember").getAsBoolean();

        // Build response
        JsonObject out = new JsonObject();
        out.addProperty("success", result.success());
        out.addProperty("message", result.message());

        if (result.success()) {
            out.addProperty("final_url", result.finalUrl());
            out.addProperty("cookie_count", result.cookies() != null ? result.cookies().size() : 0);
            out.addProperty("cookie_header_length", result.cookieHeader() != null ? result.cookieHeader().length() : 0);

            // List cookie names (not values — security)
            if (result.cookies() != null) {
                JsonArray cookieNames = new JsonArray();
                result.cookies().forEach(c -> cookieNames.add(c.name));
                out.add("cookie_names", cookieNames);
            }

            // Persist profile on successful login when remember=true
            if (remember && profileManager != null) {
                String persistedName = persistProfileForRemember(profile);
                if (persistedName != null) {
                    out.addProperty("persisted_as", persistedName);
                    out.addProperty("persisted_to", profileManager.getConfigPathString());
                } else {
                    out.addProperty("persist_warning",
                            "remember=true but failed to persist (profile has no loginUrl or manager unavailable)");
                }
            }

            out.addProperty("note", "Cookies have been injected into auth config. "
                    + "You can now use send_request to test APIs with these cookies. "
                    + "Use browser_discover or browser_explore to find and trigger APIs."
                    + (out.has("persisted_as")
                            ? " Account has been saved as '" + out.get("persisted_as").getAsString()
                              + "' and will be reused automatically on the same domain."
                            : ""));
        } else {
            out.addProperty("troubleshooting",
                    "Common causes: 1) Wrong credentials, "
                    + "2) Login form not detected (try custom selectors), "
                    + "3) SSO redirect not handled (try strategy='sso_buc'), "
                    + "4) CAPTCHA blocking (manual login required). "
                    + "Check Burp's HTTP history for the login request/response.");
        }

        return out.toString();
    }

    /**
     * Persist the given profile under an auto-generated name based on its loginUrl domain.
     *
     * <p>Upsert semantics: if a profile with the same generated name already exists, it is
     * replaced (handles the common case of user re-logging in with new credentials).
     *
     * <p>Package-private for testing.
     *
     * @return the generated profile name, or null if persistence was skipped (no loginUrl)
     */
    String persistProfileForRemember(LoginProfile profile) {
        if (profile == null || profile.loginUrl() == null || profile.loginUrl().isEmpty()) {
            return null;
        }
        String domain = extractDomain(profile.loginUrl());
        if (domain == null || domain.isEmpty()) {
            return null;
        }
        String generatedName = "auto-" + domain;

        LoginProfile persisted = new LoginProfile(
                generatedName,
                profile.loginUrl(),
                profile.username(),
                profile.password(),
                profile.strategy(),
                profile.formSelectors(),
                profile.successIndicators(),
                profile.persistCookies()
        );

        // Upsert: update if exists, otherwise add
        if (profileManager.findByName(generatedName).isPresent()) {
            boolean updated = profileManager.update(persisted);
            ctx.logger().info("[BrowserLogin] remember: updated profile '%s' (success=%s)",
                    generatedName, updated);
        } else {
            boolean added = profileManager.add(persisted);
            ctx.logger().info("[BrowserLogin] remember: added profile '%s' (success=%s)",
                    generatedName, added);
        }
        return generatedName;
    }

    /**
     * Extract the host (without port) from a URL for use in auto-generated profile names.
     */
    private static String extractDomain(String url) {
        if (url == null) return null;
        try {
            int schemeEnd = url.indexOf("://");
            if (schemeEnd < 0) return null;
            int pathStart = url.indexOf('/', schemeEnd + 3);
            String host = pathStart > 0 ? url.substring(schemeEnd + 3, pathStart) : url.substring(schemeEnd + 3);
            int portIdx = host.indexOf(':');
            return portIdx > 0 ? host.substring(0, portIdx) : host;
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Resolve a LoginProfile from tool arguments.
     *
     * <p>Priority:
     * <ol>
     *   <li>By profile_name (exact match)</li>
     *   <li>By login_url domain match</li>
     *   <li>Default profile</li>
     *   <li>Build inline from arguments</li>
     * </ol>
     */
    private LoginProfile resolveProfile(JsonObject args) {
        // 1. By profile_name
        String profileName = getStr(args, "profile_name");
        if (profileName != null && !profileName.isEmpty()) {
            Optional<LoginProfile> found = profileManager.findByName(profileName);
            if (found.isPresent()) return found.get();
        }

        // 2. By login_url domain
        String loginUrl = getStr(args, "login_url");
        if (loginUrl != null && !loginUrl.isEmpty()) {
            Optional<LoginProfile> found = profileManager.findByUrl(loginUrl);
            if (found.isPresent()) return found.get();
        }

        // 3. Default profile — but ONLY when its domain matches the current
        //    target being analyzed. Blindly returning the first profile is
        //    dangerous when the user has unrelated placeholder profiles (e.g.
        //    "prod" pointing at example.com) configured: the agent would end
        //    up trying to log into a completely different site.
        if (profileName == null && loginUrl == null) {
            Optional<LoginProfile> defaultProfile = profileManager.getDefault();
            if (defaultProfile.isPresent()) {
                LoginProfile candidate = defaultProfile.get();
                String targetDomain = currentTargetDomain();
                String profileDomain = extractDomain(candidate.loginUrl());
                if (targetDomain == null
                        || profileDomain == null
                        || targetDomain.equals(profileDomain)
                        || targetDomain.endsWith("." + profileDomain)) {
                    return candidate;
                }
                // Domain mismatch: fall through and let step 4 fail with a
                // clear error so the agent knows it MUST pass login_url.
                ctx.logger().info("[BrowserLogin] 默认 profile '%s' 的域名 '%s' 与当前目标 '%s' 不匹配，跳过回退",
                        candidate.name(), profileDomain, targetDomain);
            }
        }

        // 4. Build inline from arguments
        if (loginUrl != null && !loginUrl.isEmpty()) {
            String username = getStr(args, "username");
            String password = getStr(args, "password");
            if (username == null || password == null) {
                return null; // Need credentials
            }

            String strategyStr = getStr(args, "strategy");
            LoginProfile.LoginStrategy strategy = LoginProfile.LoginStrategy.AUTO;
            if ("sso_buc".equalsIgnoreCase(strategyStr)) {
                strategy = LoginProfile.LoginStrategy.SSO_BUC;
            } else if ("custom_form".equalsIgnoreCase(strategyStr)) {
                strategy = LoginProfile.LoginStrategy.CUSTOM_FORM;
            }

            java.util.Map<String, String> selectors = new java.util.LinkedHashMap<>();
            String userSel = getStr(args, "username_selector");
            String pwdSel = getStr(args, "password_selector");
            String subSel = getStr(args, "submit_selector");
            if (userSel != null) selectors.put(LoginProfile.SELECTOR_USERNAME, userSel);
            if (pwdSel != null) selectors.put(LoginProfile.SELECTOR_PASSWORD, pwdSel);
            if (subSel != null) selectors.put(LoginProfile.SELECTOR_SUBMIT, subSel);

            return new LoginProfile(
                    "inline", loginUrl, username, password,
                    strategy, selectors,
                    java.util.List.of("/dashboard", "/home", "/index"),
                    true
            );
        }

        return null;
    }

    private String listProfileNames() {
        var profiles = profileManager.getAll();
        if (profiles.isEmpty()) return "(none configured)";
        return profiles.stream()
                .map(LoginProfile::name)
                .collect(java.util.stream.Collectors.joining(", "));
    }

    /**
     * Extract the domain (host, no port) of the ApiEntry currently bound to
     * this tool invocation. Returns null when no entry is attached (e.g.
     * chat-only / standalone mode) — callers treat null as "no mismatch".
     */
    private String currentTargetDomain() {
        if (ctx == null || ctx.entry() == null) return null;
        // Prefer the last-seen URL (full authority); fall back to the
        // stored domain field on the entry when no request has been sent.
        String url = ctx.entry().getLastUrl();
        if (url != null && !url.isEmpty()) {
            String d = extractDomain(url);
            if (d != null) return d;
        }
        String dom = ctx.entry().getDomain();
        if (dom == null || dom.isEmpty()) return null;
        int portIdx = dom.indexOf(':');
        return portIdx > 0 ? dom.substring(0, portIdx) : dom;
    }

    private JsonObject prop(String type, String desc) {
        JsonObject p = new JsonObject();
        p.addProperty("type", type);
        p.addProperty("description", desc);
        return p;
    }

    private String getStr(JsonObject obj, String key) {
        return obj.has(key) && !obj.get(key).isJsonNull() ? obj.get(key).getAsString() : null;
    }

    private String errorJson(String msg) {
        JsonObject out = new JsonObject();
        out.addProperty("success", false);
        out.addProperty("error", msg);
        return out.toString();
    }
}
