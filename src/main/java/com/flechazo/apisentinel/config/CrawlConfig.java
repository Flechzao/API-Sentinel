package com.flechazo.apisentinel.config;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

import java.util.ArrayList;
import java.util.List;

/**
 * Configuration for auto-crawl (full-site scanning).
 *
 * <p>Combines browser_login + browser_explore + browser_discover into
 * a single automated workflow that:
 * <ol>
 *   <li>Logs in to the application</li>
 *   <li>Discovers all frontend routes and APIs</li>
 *   <li>Explores each undiscovered API to find its trigger path</li>
 *   <li>Registers discovered APIs for security analysis</li>
 * </ol>
 *
 * @param profileName     login profile name to use
 * @param startUrl        starting URL for crawling
 * @param maxPages        maximum pages to visit during discovery
 * @param exploreDepth    exploration depth for browser_explore (1-15)
 * @param skipDiscovered  skip APIs already in the repository
 * @param excludePatterns URL patterns to exclude (regex)
 * @param autoAnalyze     automatically trigger security analysis after crawl
 */
public record CrawlConfig(
        String profileName,
        String startUrl,
        int maxPages,
        int exploreDepth,
        boolean skipDiscovered,
        List<String> excludePatterns,
        boolean autoAnalyze
) {

    /** Default max pages to visit. */
    public static final int DEFAULT_MAX_PAGES = 50;

    /** Default exploration depth. */
    public static final int DEFAULT_EXPLORE_DEPTH = 8;

    /**
     * Create a default config for the given URL.
     */
    public static CrawlConfig defaultFor(String startUrl) {
        return new CrawlConfig(
                null,
                startUrl,
                DEFAULT_MAX_PAGES,
                DEFAULT_EXPLORE_DEPTH,
                true,
                List.of(".*\\.(css|js|png|jpg|svg|ico|woff|ttf)$"),
                true
        );
    }

    /**
     * Check if a URL matches any exclude pattern.
     */
    public boolean isExcluded(String url) {
        if (url == null || excludePatterns == null) return false;
        for (String pattern : excludePatterns) {
            if (url.matches(pattern)) return true;
        }
        return false;
    }

    /**
     * Convert to JSON.
     */
    public JsonObject toJson() {
        JsonObject obj = new JsonObject();
        if (profileName != null) obj.addProperty("profileName", profileName);
        if (startUrl != null) obj.addProperty("startUrl", startUrl);
        obj.addProperty("maxPages", maxPages);
        obj.addProperty("exploreDepth", exploreDepth);
        obj.addProperty("skipDiscovered", skipDiscovered);
        obj.addProperty("autoAnalyze", autoAnalyze);

        if (excludePatterns != null && !excludePatterns.isEmpty()) {
            JsonArray arr = new JsonArray();
            excludePatterns.forEach(arr::add);
            obj.add("excludePatterns", arr);
        }

        return obj;
    }

    /**
     * Parse from JSON.
     */
    public static CrawlConfig fromJson(JsonObject obj) {
        String profileName = obj.has("profileName") ? obj.get("profileName").getAsString() : null;
        String startUrl = obj.has("startUrl") ? obj.get("startUrl").getAsString() : null;
        int maxPages = obj.has("maxPages") ? obj.get("maxPages").getAsInt() : DEFAULT_MAX_PAGES;
        int exploreDepth = obj.has("exploreDepth") ? obj.get("exploreDepth").getAsInt() : DEFAULT_EXPLORE_DEPTH;
        boolean skipDiscovered = !obj.has("skipDiscovered") || obj.get("skipDiscovered").getAsBoolean();
        boolean autoAnalyze = !obj.has("autoAnalyze") || obj.get("autoAnalyze").getAsBoolean();

        List<String> excludePatterns = new ArrayList<>();
        if (obj.has("excludePatterns")) {
            for (JsonElement el : obj.getAsJsonArray("excludePatterns")) {
                excludePatterns.add(el.getAsString());
            }
        }

        return new CrawlConfig(profileName, startUrl, maxPages, exploreDepth,
                skipDiscovered, excludePatterns, autoAnalyze);
    }
}
