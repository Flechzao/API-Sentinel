package com.flechazo.apisentinel.ai.agent.tool;

import com.flechazo.apisentinel.browser.AgentBrowserCli;
import com.flechazo.apisentinel.browser.ApiExtractionService;
import com.flechazo.apisentinel.browser.AuthContext;
import com.flechazo.apisentinel.browser.BrowserService;
import com.flechazo.apisentinel.config.AppConfig;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

/**
 * Agent tool for extracting authentication credentials from browser session.
 *
 * <p>Uses agent-browser to extract cookies, localStorage, and bearer tokens
 * from the current browser session. Credentials are injected into AppConfig
 * for use by send_request and other tools.
 *
 * <p>Use when: you have an authenticated browser session and need to extract
 * credentials for API testing.
 */
public class ExtractAuthTool implements AgentTool {

    private final ToolContext ctx;
    private final BrowserService browserService;
    private final AppConfig appConfig;
    private final ApiExtractionService extractionService;

    public ExtractAuthTool(ToolContext ctx, BrowserService browserService, AppConfig appConfig) {
        this.ctx = ctx;
        this.browserService = browserService;
        this.appConfig = appConfig;
        this.extractionService = new ApiExtractionService(browserService);
    }

    @Override
    public String name() { return "extract_auth"; }

    @Override
    public String description() {
        return "Extract authentication credentials (cookies, tokens) from the current browser session. "
             + "Use when: you have an authenticated browser session and need credentials for API testing. "
             + "Extracts: cookies, localStorage (JWT tokens), Authorization headers. "
             + "Credentials are automatically injected into auth config for use by send_request. "
             + "Requires: agent-browser CLI installed (run 'npm install -g agent-browser && agent-browser install').";
    }

    @Override
    public JsonObject inputSchema() {
        JsonObject schema = new JsonObject();
        schema.addProperty("type", "object");

        JsonObject props = new JsonObject();
        props.add("inject_to_config", prop("boolean",
                "Whether to inject extracted credentials into AppConfig (default: true). "
                + "When true, cookies are set in authSessionACookie and bearer token in authHeader."));

        schema.add("properties", props);
        schema.add("required", JsonParser.parseString("[]"));
        return schema;
    }

    @Override
    public String execute(String argumentsJson) {
        JsonObject args = JsonParser.parseString(argumentsJson).getAsJsonObject();
        boolean injectToConfig = args.has("inject_to_config") 
            ? args.get("inject_to_config").getAsBoolean() 
            : true;

        // Check if agent-browser is available
        AgentBrowserCli cli = new AgentBrowserCli();
        if (!cli.isAvailable()) {
            return errorJson(
                "agent-browser CLI not found. Install with: "
                + "'npm install -g agent-browser && agent-browser install'. "
                + "Then restart Burp Suite."
            );
        }

        try {
            // Extract auth context
            AuthContext authContext = extractionService.extractAuthContext();

            // Build response
            JsonObject out = new JsonObject();
            out.addProperty("success", true);
            out.addProperty("cookie_count", authContext.cookies.size());
            out.addProperty("local_storage_count", authContext.localStorage.size());
            out.addProperty("bearer_token_present", authContext.bearerToken != null);

            // List cookie names (not values — security)
            JsonArray cookieNames = new JsonArray();
            authContext.cookies.forEach(c -> cookieNames.add(c.name));
            out.add("cookie_names", cookieNames);

            // List localStorage keys (not values — security)
            JsonArray storageKeys = new JsonArray();
            authContext.localStorage.keySet().forEach(storageKeys::add);
            out.add("local_storage_keys", storageKeys);

            // Inject into config if requested
            if (injectToConfig && authContext.hasAuth()) {
                // Inject cookies
                if (!authContext.cookies.isEmpty()) {
                    appConfig.setAuthSessionACookie(authContext.getCookieString());
                    out.addProperty("cookie_injected", true);
                }

                // Inject bearer token
                if (authContext.bearerToken != null) {
                    appConfig.setAuthHeader(authContext.getAuthorizationHeader());
                    out.addProperty("bearer_token_injected", true);
                }

                out.addProperty("note", 
                    "Credentials injected into auth config. "
                    + "You can now use send_request to test APIs with these credentials."
                );
            } else if (!authContext.hasAuth()) {
                out.addProperty("warning", 
                    "No authentication credentials found in browser session. "
                    + "Make sure you are logged in before extracting auth."
                );
            }

            return out.toString();

        } catch (Exception e) {
            ctx.logger().warn("[ExtractAuthTool] 提取认证凭证失败: %s", e.getMessage());
            return errorJson("Failed to extract auth: " + e.getMessage()
                + ". Make sure agent-browser daemon is running and browser is open.");
        }
    }

    private JsonObject prop(String type, String desc) {
        JsonObject p = new JsonObject();
        p.addProperty("type", type);
        p.addProperty("description", desc);
        return p;
    }

    private String errorJson(String msg) {
        JsonObject out = new JsonObject();
        out.addProperty("success", false);
        out.addProperty("error", msg);
        return out.toString();
    }
}
