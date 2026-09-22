package com.flechazo.apisentinel.browser;

import com.flechazo.apisentinel.config.AppConfig;
import com.flechazo.apisentinel.config.LoginProfile;
import com.flechazo.apisentinel.config.LoginProfile.LoginStrategy;
import com.flechazo.apisentinel.logging.LeveledLogger;
import com.microsoft.playwright.*;
import com.microsoft.playwright.options.Cookie;
import com.microsoft.playwright.options.LoadState;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.stream.Collectors;

/**
 * Handles automatic browser login flows.
 *
 * <p>Supports multiple login strategies:
 * <ul>
 *   <li>{@link LoginStrategy#AUTO} — automatically detect login form elements</li>
 *   <li>{@link LoginStrategy#CUSTOM_FORM} — use configured CSS selectors</li>
 *   <li>{@link LoginStrategy#SSO_BUC} — handle SSO/BUC redirect flows</li>
 * </ul>
 *
 * <p>After successful login, cookies are extracted and injected into
 * {@link AppConfig#setAuthSessionACookie(String)} for use by other tools.
 *
 * <p>Thread-safe: login operations are synchronized on the BrowserManager instance.
 */
public class BrowserLogin {

    private static final int LOGIN_TIMEOUT_MS = 30000;
    private static final int SSO_REDIRECT_WAIT_MS = 10000;

    private final LeveledLogger logger;
    private final BrowserManager browserManager;

    /** Optional reference to AppConfig for cookie injection. */
    private AppConfig appConfig;

    /** Path to persist cookies (if profile.persistCookies is true). */
    private static final String COOKIE_CACHE_DIR = ".api-sentinel/cookies";

    public BrowserLogin(LeveledLogger logger, BrowserManager browserManager) {
        this.logger = logger;
        this.browserManager = browserManager;
    }

    /**
     * Set the AppConfig reference for cookie injection.
     */
    public void setAppConfig(AppConfig appConfig) {
        this.appConfig = appConfig;
    }

    /**
     * Perform login using the given profile.
     *
     * @param profile the login configuration
     * @return login result with cookies and status
     */
    public LoginResult login(LoginProfile profile) {
        if (profile == null) {
            return LoginResult.failure("Login profile is null");
        }
        if (profile.loginUrl() == null || profile.loginUrl().isEmpty()) {
            return LoginResult.failure("Login URL is empty");
        }

        logger.info("[BrowserLogin] 开始登录: %s (策略: %s)", profile.loginUrl(), profile.strategy());

        Page page = null;
        try {
            page = browserManager.getSharedPage();

            // Step 1: Navigate to login page
            if (!navigateToLogin(page, profile)) {
                return LoginResult.failure("无法导航到登录页: " + profile.loginUrl());
            }

            // Step 2: Handle SSO redirect if applicable
            if (profile.strategy() == LoginStrategy.SSO_BUC) {
                handleSsoRedirect(page);
            }

            // Step 3: Locate and fill login form
            if (!fillLoginForm(page, profile)) {
                return LoginResult.failure("无法定位或填写登录表单");
            }

            // Step 4: Submit and wait for success
            if (!submitAndWaitForSuccess(page, profile)) {
                return LoginResult.failure("登录提交后未检测到成功标志（超时或凭证错误）");
            }

            // Step 5: Extract cookies
            List<Cookie> cookies = page.context().cookies();
            String cookieHeader = cookies.stream()
                    .map(c -> c.name + "=" + c.value)
                    .collect(Collectors.joining("; "));

            // Step 6: Inject into AppConfig
            if (appConfig != null) {
                appConfig.setAuthSessionACookie(cookieHeader);
                logger.debug("[BrowserLogin] Cookie 已注入 AppConfig (%d 个 cookie)", cookies.size());
            }

            // Step 7: Optionally persist cookies
            if (profile.persistCookies()) {
                persistCookies(profile.name(), cookies);
            }

            logger.info("[BrowserLogin] 登录成功: %s (%d 个 cookie)", profile.name(), cookies.size());
            return LoginResult.success(cookieHeader, cookies, page.url());

        } catch (Exception e) {
            logger.error("[BrowserLogin] 登录异常: %s", e.getMessage());
            return LoginResult.failure("登录异常: " + e.getMessage());
        } finally {
            // Don't close the shared page — it's reused across tool calls
            // Only close if it's not the shared page (shouldn't happen, but defensive)
            if (page != null && !browserManager.isSharedPage(page)) {
                try { page.close(); } catch (Exception ignored) {}
            }
        }
    }

    /**
     * Navigate to the login page.
     */
    private boolean navigateToLogin(Page page, LoginProfile profile) {
        try {
            page.navigate(profile.loginUrl(), new Page.NavigateOptions()
                    .setTimeout(LOGIN_TIMEOUT_MS)
                    .setWaitUntil(com.microsoft.playwright.options.WaitUntilState.DOMCONTENTLOADED));

            // Wait for page to be interactive
            page.waitForLoadState(LoadState.NETWORKIDLE,
                    new Page.WaitForLoadStateOptions().setTimeout(10000));

            logger.debug("[BrowserLogin] 导航完成: %s", page.url());
            return true;
        } catch (Exception e) {
            logger.warn("[BrowserLogin] 导航失败: %s", e.getMessage());
            // Navigation might still have partially succeeded (e.g., redirected to SSO)
            return page.url() != null && !page.url().isEmpty();
        }
    }

    /**
     * Handle SSO/BUC redirect chains.
     *
     * <p>SSO flows typically redirect through multiple pages before reaching
     * the actual login form. We wait for the redirects to settle.
     */
    private void handleSsoRedirect(Page page) {
        logger.debug("[BrowserLogin] 等待 SSO 重定向完成...");
        try {
            // Wait for navigation to settle (no more redirects)
            page.waitForLoadState(LoadState.NETWORKIDLE,
                    new Page.WaitForLoadStateOptions().setTimeout(SSO_REDIRECT_WAIT_MS));

            // Check if we're on a different domain (SSO page)
            String currentUrl = page.url();
            logger.debug("[BrowserLogin] SSO 重定向后 URL: %s", currentUrl);

            // Some SSO pages have a "Continue" or "确认" button
            tryClickSsoConfirm(page);

        } catch (Exception e) {
            logger.debug("[BrowserLogin] SSO 重定向等待超时 (可能已到达登录页): %s", e.getMessage());
        }
    }

    /**
     * Try to click common SSO confirmation buttons.
     */
    private void tryClickSsoConfirm(Page page) {
        String[] confirmSelectors = {
                "button:has-text('确认')", "button:has-text('继续')",
                "button:has-text('Confirm')", "button:has-text('Continue')",
                "button:has-text('授权')", "button:has-text('Authorize')",
                "#confirm-btn", ".sso-confirm"
        };

        for (String selector : confirmSelectors) {
            try {
                ElementHandle el = page.querySelector(selector);
                if (el != null && el.isVisible()) {
                    el.click();
                    logger.debug("[BrowserLogin] 点击了 SSO 确认按钮: %s", selector);
                    page.waitForLoadState(LoadState.NETWORKIDLE,
                            new Page.WaitForLoadStateOptions().setTimeout(5000));
                    return;
                }
            } catch (Exception ignored) {}
        }
    }

    /**
     * Locate and fill the login form.
     */
    private boolean fillLoginForm(Page page, LoginProfile profile) {
        // Step 1: Find form elements
        FormElements form;
        if (profile.strategy() == LoginStrategy.CUSTOM_FORM && !profile.formSelectors().isEmpty()) {
            form = locateByCustomSelectors(page, profile);
        } else {
            form = locateByAutoDetection(page);
        }

        if (form == null) {
            logger.warn("[BrowserLogin] 无法定位登录表单");
            return false;
        }

        // Step 2: Fill username
        try {
            form.usernameInput.click();
            form.usernameInput.fill(profile.username());
            logger.debug("[BrowserLogin] 已填写用户名");
        } catch (Exception e) {
            logger.warn("[BrowserLogin] 填写用户名失败: %s", e.getMessage());
            return false;
        }

        // Step 3: Fill password
        try {
            form.passwordInput.click();
            form.passwordInput.fill(profile.password());
            logger.debug("[BrowserLogin] 已填写密码");
        } catch (Exception e) {
            logger.warn("[BrowserLogin] 填写密码失败: %s", e.getMessage());
            return false;
        }

        return true;
    }

    /**
     * Locate form elements using auto-detection heuristics.
     *
     * <p>Strategy:
     * <ol>
     *   <li>Find {@code input[type=password]} — this is almost always the password field</li>
     *   <li>Walk up to the nearest {@code <form>} ancestor</li>
     *   <li>Find username input within the form (text/email input)</li>
     *   <li>Find submit button within the form</li>
     * </ol>
     */
    private FormElements locateByAutoDetection(Page page) {
        // Find password input
        ElementHandle pwdInput = page.querySelector("input[type=password]:visible");
        if (pwdInput == null) {
            // Try without :visible (some pages use opacity tricks)
            pwdInput = page.querySelector("input[type=password]");
        }
        if (pwdInput == null) {
            logger.debug("[BrowserLogin] 未找到 password input");
            return null;
        }

        // Find the enclosing form
        ElementHandle form = null;
        try {
            form = pwdInput.evaluateHandle("el => el.closest('form')").asElement();
        } catch (Exception ignored) {}

        // Find username input
        ElementHandle userInput = null;
        String[] userSelectors = {
                "input[type=text]", "input[type=email]",
                "input[name*=user]", "input[name*=account]", "input[name*=login]",
                "input[id*=user]", "input[id*=account]", "input[id*=login]",
                "input[placeholder*=用户]", "input[placeholder*=账号]",
                "input[placeholder*=user]", "input[placeholder*=email]"
        };

        // Search within form first, then page-wide
        ElementHandle searchScope = form != null ? form : page.querySelector("body");
        for (String sel : userSelectors) {
            try {
                userInput = searchScope.querySelector(sel);
                if (userInput != null && userInput.isVisible()) break;
                userInput = null;
            } catch (Exception ignored) {}
        }

        if (userInput == null) {
            // Fallback: find the input immediately before the password input
            try {
                userInput = pwdInput.evaluateHandle(
                        "el => { const inputs = el.closest('form')?.querySelectorAll('input') || document.querySelectorAll('input'); " +
                                "const arr = Array.from(inputs).filter(i => i.type !== 'password' && i.type !== 'hidden'); " +
                                "return arr[0] || null; }"
                ).asElement();
            } catch (Exception ignored) {}
        }

        if (userInput == null) {
            logger.debug("[BrowserLogin] 未找到 username input");
            return null;
        }

        // Find submit button
        ElementHandle submitBtn = null;
        String[] submitSelectors = {
                "button[type=submit]", "input[type=submit]",
                ".login-btn", ".submit-btn", "#login-btn", "#submit-btn",
                "button:has-text('登录')", "button:has-text('Login')",
                "button:has-text('Sign in')", "button:has-text('登入')"
        };

        for (String sel : submitSelectors) {
            try {
                submitBtn = searchScope.querySelector(sel);
                if (submitBtn != null && submitBtn.isVisible()) break;
                submitBtn = null;
            } catch (Exception ignored) {}
        }

        if (submitBtn == null) {
            // Fallback: any button in the form
            try {
                submitBtn = searchScope.querySelector("button");
            } catch (Exception ignored) {}
        }

        logger.debug("[BrowserLogin] 自动检测表单: user=%s, pwd=%s, submit=%s",
                userInput != null, pwdInput != null, submitBtn != null);

        return new FormElements(userInput, pwdInput, submitBtn);
    }

    /**
     * Locate form elements using custom CSS selectors from the profile.
     */
    private FormElements locateByCustomSelectors(Page page, LoginProfile profile) {
        try {
            ElementHandle userInput = page.querySelector(profile.getUsernameSelector());
            ElementHandle pwdInput = page.querySelector(profile.getPasswordSelector());
            ElementHandle submitBtn = page.querySelector(profile.getSubmitSelector());

            if (userInput == null || pwdInput == null) {
                logger.warn("[BrowserLogin] 自定义选择器未匹配到元素: user=%s, pwd=%s",
                        profile.getUsernameSelector(), profile.getPasswordSelector());
                return null;
            }

            logger.debug("[BrowserLogin] 使用自定义选择器定位表单");
            return new FormElements(userInput, pwdInput, submitBtn);
        } catch (Exception e) {
            logger.warn("[BrowserLogin] 自定义选择器定位失败: %s", e.getMessage());
            return null;
        }
    }

    /**
     * Submit the login form and wait for success indicators.
     */
    private boolean submitAndWaitForSuccess(Page page, LoginProfile profile) {
        // Click submit button or press Enter
        FormElements form = locateByAutoDetection(page); // re-locate after fill
        if (form == null) {
            // Try custom selectors
            if (profile.strategy() == LoginStrategy.CUSTOM_FORM) {
                form = locateByCustomSelectors(page, profile);
            }
        }

        try {
            if (form != null && form.submitButton != null) {
                form.submitButton.click();
            } else {
                // Fallback: press Enter in password field
                page.keyboard().press("Enter");
            }
        } catch (Exception e) {
            logger.warn("[BrowserLogin] 提交按钮点击失败，尝试 Enter: %s", e.getMessage());
            page.keyboard().press("Enter");
        }

        // Wait for login to complete
        String urlBefore = page.url();

        // Strategy 1: Wait for URL change (most reliable)
        try {
            page.waitForURL(url -> !url.contains("/login") && !url.contains("/sso")
                            && !url.contains("/auth") && !url.contains("/signin")
                            && !url.equals(urlBefore),
                    new Page.WaitForURLOptions().setTimeout(LOGIN_TIMEOUT_MS));
            logger.debug("[BrowserLogin] URL 变化检测到: %s → %s", urlBefore, page.url());
            return true;
        } catch (Exception ignored) {}

        // Strategy 2: Check success indicators from profile
        for (String indicator : profile.successIndicators()) {
            try {
                if (page.url().contains(indicator)) {
                    logger.debug("[BrowserLogin] 成功指标命中 (URL): %s", indicator);
                    return true;
                }
                // Check if element exists
                ElementHandle el = page.querySelector(indicator);
                if (el != null && el.isVisible()) {
                    logger.debug("[BrowserLogin] 成功指标命中 (元素): %s", indicator);
                    return true;
                }
            } catch (Exception ignored) {}
        }

        // Strategy 3: Check if cookies were set (indicates successful auth)
        List<Cookie> cookies = page.context().cookies();
        boolean hasAuthCookie = cookies.stream()
                .anyMatch(c -> c.name.toLowerCase().contains("session")
                        || c.name.toLowerCase().contains("token")
                        || c.name.toLowerCase().contains("auth")
                        || c.name.toLowerCase().contains("sid")
                        || c.name.toLowerCase().contains("jwt"));

        if (hasAuthCookie) {
            logger.debug("[BrowserLogin] 检测到认证 Cookie");
            return true;
        }

        // Strategy 4: Check if we're no longer on a login-like page
        String currentUrl = page.url();
        if (!currentUrl.contains("/login") && !currentUrl.contains("/sso")
                && !currentUrl.contains("/auth") && !currentUrl.contains("/signin")
                && !currentUrl.equals(urlBefore)) {
            logger.debug("[BrowserLogin] URL 已变化，推断登录成功: %s", currentUrl);
            return true;
        }

        logger.warn("[BrowserLogin] 未检测到登录成功标志 (当前 URL: %s)", currentUrl);
        return false;
    }

    /**
     * Persist cookies to disk for future reuse.
     */
    private void persistCookies(String profileName, List<Cookie> cookies) {
        try {
            Path dir = Paths.get(System.getProperty("user.home"), COOKIE_CACHE_DIR);
            Files.createDirectories(dir);
            Path file = dir.resolve(sanitizeFileName(profileName) + ".json");

            // Simple JSON serialization
            StringBuilder sb = new StringBuilder();
            sb.append("{\"cookies\":[");
            for (int i = 0; i < cookies.size(); i++) {
                Cookie c = cookies.get(i);
                if (i > 0) sb.append(",");
                sb.append(String.format("{\"name\":\"%s\",\"value\":\"%s\",\"domain\":\"%s\",\"path\":\"%s\"}",
                        escape(c.name), escape(c.value), escape(c.domain), escape(c.path)));
            }
            sb.append("],\"timestamp\":").append(System.currentTimeMillis()).append("}");

            Files.writeString(file, sb.toString(), StandardCharsets.UTF_8);
            logger.debug("[BrowserLogin] Cookie 已持久化: %s (%d 个)", file, cookies.size());
        } catch (Exception e) {
            logger.warn("[BrowserLogin] Cookie 持久化失败: %s", e.getMessage());
        }
    }

    /**
     * Load persisted cookies for a profile (if available and not expired).
     *
     * @param profileName the profile name
     * @param maxAgeMs    maximum age of cached cookies (0 = no limit)
     * @return cookie header string, or null if not available/expired
     */
    public String loadCachedCookies(String profileName, long maxAgeMs) {
        try {
            Path file = Paths.get(System.getProperty("user.home"), COOKIE_CACHE_DIR,
                    sanitizeFileName(profileName) + ".json");
            if (!Files.exists(file)) return null;

            String content = Files.readString(file, StandardCharsets.UTF_8);
            // Simple timestamp check
            int tsIdx = content.indexOf("\"timestamp\":");
            if (tsIdx > 0 && maxAgeMs > 0) {
                String tsStr = content.substring(tsIdx + 12, content.indexOf("}", tsIdx));
                long timestamp = Long.parseLong(tsStr.trim());
                if (System.currentTimeMillis() - timestamp > maxAgeMs) {
                    logger.debug("[BrowserLogin] 缓存 Cookie 已过期");
                    return null;
                }
            }

            // For now, return the raw content — full cookie injection would use BrowserContext.addCookies()
            logger.debug("[BrowserLogin] 找到缓存 Cookie: %s", file);
            return content;
        } catch (Exception e) {
            logger.debug("[BrowserLogin] 加载缓存 Cookie 失败: %s", e.getMessage());
            return null;
        }
    }

    private String sanitizeFileName(String name) {
        return name.replaceAll("[^a-zA-Z0-9_-]", "_");
    }

    private String escape(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\").replace("\"", "\\\"");
    }

    // ========== Data Types ==========

    /**
     * Holds references to located form elements.
     */
    record FormElements(ElementHandle usernameInput, ElementHandle passwordInput, ElementHandle submitButton) {}

    /**
     * Result of a login attempt.
     *
     * @param success       whether login succeeded
     * @param cookieHeader  the Cookie header value (semicolon-separated)
     * @param cookies       raw cookie list from Playwright
     * @param finalUrl      the URL after login (may differ from loginUrl due to redirects)
     * @param message       human-readable status message
     */
    public record LoginResult(
            boolean success,
            String cookieHeader,
            List<Cookie> cookies,
            String finalUrl,
            String message
    ) {
        public static LoginResult success(String cookieHeader, List<Cookie> cookies, String finalUrl) {
            return new LoginResult(true, cookieHeader, cookies, finalUrl,
                    String.format("登录成功 (%d 个 cookie)", cookies.size()));
        }

        public static LoginResult failure(String message) {
            return new LoginResult(false, "", List.of(), "", message);
        }
    }
}
