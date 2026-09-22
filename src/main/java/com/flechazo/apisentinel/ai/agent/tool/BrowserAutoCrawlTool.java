package com.flechazo.apisentinel.ai.agent.tool;

import com.flechazo.apisentinel.browser.AutoCrawlService;
import com.flechazo.apisentinel.browser.AutoCrawlService.CrawlResult;
import com.flechazo.apisentinel.browser.BrowserService;
import com.flechazo.apisentinel.config.CrawlConfig;
import com.flechazo.apisentinel.config.LoginProfileManager;
import com.flechazo.apisentinel.repository.ApiRepository;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Agent tool for one-click full-site auto-crawl.
 *
 * <p>Orchestrates the complete workflow:
 * <ol>
 *   <li>Login (using configured profile)</li>
 *   <li>Discover all routes and APIs</li>
 *   <li>Explore undiscovered APIs to find trigger paths</li>
 *   <li>Register all APIs for security analysis</li>
 * </ol>
 *
 * <p>Use when: you want a comprehensive scan of all APIs in an application
 * without manually specifying each endpoint.
 */
public class BrowserAutoCrawlTool implements AgentTool {

    private final ToolContext ctx;
    private final BrowserService browserService;
    private final AutoCrawlService crawlService;

    public BrowserAutoCrawlTool(ToolContext ctx, BrowserService browserService,
                                LoginProfileManager profileManager, ApiRepository apiRepository) {
        this.ctx = ctx;
        this.browserService = browserService;
        this.crawlService = new AutoCrawlService(
                ctx.logger(), browserService, profileManager,
                ctx.provider(), apiRepository);
    }

    @Override
    public String name() { return "browser_auto_crawl"; }

    @Override
    public String description() {
        return "One-click full-site auto-crawl: login → discover APIs → explore trigger paths → register. "
             + "Automatically scans an entire web application to find and trigger all APIs. "
             + "Use when: you want a comprehensive API inventory without manual specification, "
             + "or when onboarding a new application for security testing. "
             + "Combines browser_login + browser_discover + browser_explore in one step. "
             + "Returns: discovered APIs, exploration results, registered APIs. "
             + "All browser traffic goes through Burp proxy automatically.";
    }

    @Override
    public JsonObject inputSchema() {
        JsonObject schema = new JsonObject();
        schema.addProperty("type", "object");

        JsonObject props = new JsonObject();
        props.add("start_url", prop("string",
                "Starting URL for crawling (required). Usually the app homepage. "
                + "Example: 'http://localhost:3000'."));
        props.add("profile_name", prop("string",
                "Login profile name to use (optional). Auto-matched by URL if omitted."));
        props.add("max_pages", prop("integer",
                "Maximum pages to visit during discovery (default: 50). "
                + "Increase for larger applications."));
        props.add("explore_depth", prop("integer",
                "Exploration depth per API (default: 8). How many clicks to try. "
                + "Increase for deeply nested menus."));
        props.add("skip_discovered", prop("boolean",
                "Skip APIs already in the repository (default: true). "
                + "Set false to re-explore all APIs."));
        props.add("exclude_patterns", prop("array",
                "URL patterns to exclude (regex array). "
                + "Example: ['.*\\\\.css$', '.*/health$']."));

        schema.add("properties", props);
        schema.add("required", JsonParser.parseString("[\"start_url\"]"));
        return schema;
    }

    @Override
    public String execute(String argumentsJson) {
        if (browserService == null) {
            return errorJson("Browser service not available. Enable browser in settings.");
        }
        if (crawlService.isRunning()) {
            return errorJson("Auto-crawl is already running. Please wait or interrupt first.");
        }

        JsonObject args = JsonParser.parseString(argumentsJson).getAsJsonObject();

        String startUrl = getStr(args, "start_url");
        if (startUrl == null || startUrl.isEmpty()) {
            return errorJson("start_url is required");
        }

        // Build config
        String profileName = getStr(args, "profile_name");
        int maxPages = args.has("max_pages") ? args.get("max_pages").getAsInt() : CrawlConfig.DEFAULT_MAX_PAGES;
        int exploreDepth = args.has("explore_depth") ? args.get("explore_depth").getAsInt() : CrawlConfig.DEFAULT_EXPLORE_DEPTH;
        boolean skipDiscovered = !args.has("skip_discovered") || args.get("skip_discovered").getAsBoolean();

        List<String> excludePatterns = new ArrayList<>();
        if (args.has("exclude_patterns") && args.get("exclude_patterns").isJsonArray()) {
            for (var el : args.getAsJsonArray("exclude_patterns")) {
                if (el.isJsonPrimitive()) excludePatterns.add(el.getAsString());
            }
        }

        CrawlConfig config = new CrawlConfig(
                profileName, startUrl, maxPages, exploreDepth,
                skipDiscovered, excludePatterns, true);

        // Run crawl
        CrawlResult result = crawlService.crawl(config);

        // Build response
        JsonObject out = new JsonObject();
        out.addProperty("success", result.success());
        out.addProperty("message", result.summary());

        if (result.success() || result.wasInterrupted()) {
            out.addProperty("total_apis", result.totalApis());
            out.addProperty("explored_apis", result.exploredApis());
            out.addProperty("success_apis", result.successApis());
            out.addProperty("registered_apis", result.registeredApis());
            out.addProperty("total_routes", result.totalRoutes());
            out.addProperty("was_interrupted", result.wasInterrupted());

            // Explored paths summary
            if (!result.exploredPaths().isEmpty()) {
                JsonObject paths = new JsonObject();
                for (Map.Entry<String, ?> entry : result.exploredPaths().entrySet()) {
                    if (entry.getValue() instanceof List<?> actions) {
                        paths.addProperty(entry.getKey(), actions.size() + " steps");
                    }
                }
                out.add("explored_paths", paths);
            }

            out.addProperty("note", "All discovered APIs have been registered. "
                    + "You can now run security analysis on them using send_request, "
                    + "heuristic_scan, or the full Agent pipeline. "
                    + "Exploration paths are cached for future use.");
        } else {
            out.addProperty("troubleshooting",
                    "Common causes: 1) Login failed — check credentials/profile, "
                    + "2) Start URL unreachable — check URL and proxy, "
                    + "3) No APIs found — try increasing max_pages or explore_depth.");
        }

        return out.toString();
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
