package com.flechazo.apisentinel.browser;

import com.flechazo.apisentinel.browser.BrowserService.BrowserAction;
import com.flechazo.apisentinel.logging.LeveledLogger;
import com.google.gson.*;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Enhanced cache for exploration paths and API templates.
 *
 * <p>Caches both UI action sequences and extracted API templates for reuse.
 * When triggering a cached API, prefers direct HTTP (API template) over UI replay.
 *
 * <p>Cache entries expire after a configurable TTL (default 7 days).
 * Persisted to {@code ~/.api-sentinel/exploration-cache.json}.
 */
public class ExplorationCache {

    private static final String CACHE_DIR = ".api-sentinel";
    private static final String CACHE_FILE = "exploration-cache.json";

    /** Default TTL: 7 days. */
    private static final long DEFAULT_TTL_MS = 7L * 24 * 60 * 60 * 1000;

    private final LeveledLogger logger;
    private final Path cachePath;
    private final long ttlMs;

    /** Cache: "METHOD /path" → CachedEntry. */
    private final Map<String, CachedEntry> cache = new ConcurrentHashMap<>();

    public ExplorationCache(LeveledLogger logger) {
        this(logger, DEFAULT_TTL_MS);
    }

    public ExplorationCache(LeveledLogger logger, long ttlMs) {
        this.logger = logger;
        this.ttlMs = ttlMs > 0 ? ttlMs : DEFAULT_TTL_MS;
        this.cachePath = Paths.get(System.getProperty("user.home"), CACHE_DIR, CACHE_FILE);
        load();
    }

    /**
     * Cache a successful exploration path (UI actions only).
     *
     * @param targetApi the target API (e.g., "POST /api/v1/roles")
     * @param actions   the action sequence that triggered the API
     */
    public void put(String targetApi, List<BrowserAction> actions) {
        put(targetApi, actions, null);
    }

    /**
     * Cache a successful exploration path with API template.
     *
     * @param targetApi    the target API (e.g., "POST /api/v1/roles")
     * @param actions      the action sequence that triggered the API (can be null)
     * @param apiTemplate  the extracted API template (can be null)
     */
    public void put(String targetApi, List<BrowserAction> actions, ApiTemplate apiTemplate) {
        if (targetApi == null) return;
        if ((actions == null || actions.isEmpty()) && apiTemplate == null) return;

        String key = normalizeKey(targetApi);
        cache.put(key, new CachedEntry(actions, apiTemplate, System.currentTimeMillis()));
        persist();

        String details = String.format(
            "%s (UI: %d steps, API template: %s)",
            targetApi,
            actions != null ? actions.size() : 0,
            apiTemplate != null ? "yes" : "no"
        );
        logger.debug("[ExplorationCache] 缓存探索路径: %s", details);
    }

    /**
     * Get a cached exploration path (UI actions only).
     *
     * @param targetApi the target API
     * @return cached action sequence, or null if not found/expired
     */
    public List<BrowserAction> get(String targetApi) {
        CachedEntry entry = getEntry(targetApi);
        return entry != null ? entry.actions : null;
    }

    /**
     * Get a cached entry (includes both UI actions and API template).
     *
     * @param targetApi the target API
     * @return cached entry, or null if not found/expired
     */
    public CachedEntry getEntry(String targetApi) {
        CachedEntry entry = cache.get(normalizeKey(targetApi));
        if (entry == null) return null;

        // Check expiration
        if (System.currentTimeMillis() - entry.timestamp > ttlMs) {
            cache.remove(normalizeKey(targetApi));
            logger.debug("[ExplorationCache] 缓存已过期: %s", targetApi);
            return null;
        }

        logger.debug("[ExplorationCache] 缓存命中: %s", targetApi);
        return entry;
    }

    /**
     * Get the API template for a cached API.
     *
     * @param targetApi the target API
     * @return API template, or null if not cached
     */
    public ApiTemplate getApiTemplate(String targetApi) {
        CachedEntry entry = getEntry(targetApi);
        return entry != null ? entry.apiTemplate : null;
    }

    /**
     * Update the API template for a cached entry.
     *
     * @param targetApi   the target API
     * @param apiTemplate the API template to cache
     */
    public void updateApiTemplate(String targetApi, ApiTemplate apiTemplate) {
        String key = normalizeKey(targetApi);
        CachedEntry existing = cache.get(key);
        
        if (existing != null) {
            cache.put(key, new CachedEntry(existing.actions, apiTemplate, existing.timestamp));
            persist();
            logger.debug("[ExplorationCache] 更新 API 模板: %s", targetApi);
        }
    }

    /**
     * Check if a target API has a cached path.
     */
    public boolean has(String targetApi) {
        return getEntry(targetApi) != null;
    }

    /**
     * Check if a target API has a cached API template (for direct HTTP).
     */
    public boolean hasApiTemplate(String targetApi) {
        CachedEntry entry = getEntry(targetApi);
        return entry != null && entry.apiTemplate != null;
    }

    /**
     * Remove a cached path.
     */
    public void remove(String targetApi) {
        cache.remove(normalizeKey(targetApi));
        persist();
    }

    /**
     * Clear all cached paths.
     */
    public void clear() {
        cache.clear();
        persist();
        logger.info("[ExplorationCache] 缓存已清空");
    }

    /**
     * Get all cached target APIs.
     */
    public Set<String> keys() {
        return Set.copyOf(cache.keySet());
    }

    /**
     * Get the number of cached entries.
     */
    public int size() {
        return cache.size();
    }

    /**
     * Get statistics about cached entries.
     *
     * @return map with counts: total, withUiPath, withApiTemplate
     */
    public Map<String, Integer> getStats() {
        int total = cache.size();
        int withUiPath = 0;
        int withApiTemplate = 0;

        for (CachedEntry entry : cache.values()) {
            if (entry.actions != null && !entry.actions.isEmpty()) {
                withUiPath++;
            }
            if (entry.apiTemplate != null) {
                withApiTemplate++;
            }
        }

        Map<String, Integer> stats = new HashMap<>();
        stats.put("total", total);
        stats.put("withUiPath", withUiPath);
        stats.put("withApiTemplate", withApiTemplate);
        return stats;
    }

    /**
     * Load cache from disk.
     */
    private void load() {
        if (!Files.exists(cachePath)) {
            logger.debug("[ExplorationCache] 缓存文件不存在: %s", cachePath);
            return;
        }

        try {
            String content = Files.readString(cachePath, StandardCharsets.UTF_8);
            JsonObject root = JsonParser.parseString(content).getAsJsonObject();

            JsonObject entries = root.has("entries") ? root.getAsJsonObject("entries") : new JsonObject();
            for (String key : entries.keySet()) {
                try {
                    JsonObject entry = entries.getAsJsonObject(key);
                    long timestamp = entry.has("timestamp") ? entry.get("timestamp").getAsLong() : 0;

                    // Parse UI actions
                    List<BrowserAction> actions = null;
                    if (entry.has("actions")) {
                        JsonArray actionsArr = entry.getAsJsonArray("actions");
                        actions = new ArrayList<>();
                        for (JsonElement el : actionsArr) {
                            JsonObject actionObj = el.getAsJsonObject();
                            actions.add(new BrowserAction(
                                    str(actionObj, "type"),
                                    str(actionObj, "selector"),
                                    str(actionObj, "value"),
                                    actionObj.has("timeout_ms") ? actionObj.get("timeout_ms").getAsInt() : 5000,
                                    str(actionObj, "url_pattern"),
                                    actionObj.has("delay_ms") ? actionObj.get("delay_ms").getAsInt() : 0
                            ));
                        }
                    }

                    // Parse API template
                    ApiTemplate apiTemplate = null;
                    if (entry.has("api_template")) {
                        JsonObject templateObj = entry.getAsJsonObject("api_template");
                        apiTemplate = new ApiTemplate();
                        apiTemplate.method = str(templateObj, "method");
                        apiTemplate.url = str(templateObj, "url");
                        apiTemplate.contentType = str(templateObj, "content_type");
                        apiTemplate.bodyTemplate = str(templateObj, "body_template");

                        // Parse auth headers
                        if (templateObj.has("auth_headers")) {
                            JsonObject headersObj = templateObj.getAsJsonObject("auth_headers");
                            apiTemplate.authHeaders = new HashMap<>();
                            for (String headerName : headersObj.keySet()) {
                                apiTemplate.authHeaders.put(headerName, headersObj.get(headerName).getAsString());
                            }
                        }

                        // Parse required params
                        if (templateObj.has("required_params")) {
                            JsonArray paramsArr = templateObj.getAsJsonArray("required_params");
                            apiTemplate.requiredParams = new ArrayList<>();
                            for (JsonElement el : paramsArr) {
                                apiTemplate.requiredParams.add(el.getAsString());
                            }
                        }
                    }

                    if ((actions != null && !actions.isEmpty()) || apiTemplate != null) {
                        cache.put(key, new CachedEntry(actions, apiTemplate, timestamp));
                    }
                } catch (Exception e) {
                    logger.warn("[ExplorationCache] 解析缓存条目失败: %s", key);
                }
            }

            logger.info("[ExplorationCache] 加载了 %d 个缓存条目", cache.size());
        } catch (Exception e) {
            logger.warn("[ExplorationCache] 加载缓存失败: %s", e.getMessage());
        }
    }

    /**
     * Persist cache to disk.
     */
    private void persist() {
        try {
            Files.createDirectories(cachePath.getParent());

            JsonObject root = new JsonObject();
            JsonObject entries = new JsonObject();

            for (Map.Entry<String, CachedEntry> entry : cache.entrySet()) {
                JsonObject entryObj = new JsonObject();
                entryObj.addProperty("timestamp", entry.getValue().timestamp);

                // Serialize UI actions
                if (entry.getValue().actions != null && !entry.getValue().actions.isEmpty()) {
                    JsonArray actionsArr = new JsonArray();
                    for (BrowserAction action : entry.getValue().actions) {
                        JsonObject actionObj = new JsonObject();
                        actionObj.addProperty("type", action.type());
                        if (action.selector() != null) actionObj.addProperty("selector", action.selector());
                        if (action.value() != null) actionObj.addProperty("value", action.value());
                        actionObj.addProperty("timeout_ms", action.timeoutMs());
                        if (action.urlPattern() != null) actionObj.addProperty("url_pattern", action.urlPattern());
                        actionObj.addProperty("delay_ms", action.delayMs());
                        actionsArr.add(actionObj);
                    }
                    entryObj.add("actions", actionsArr);
                }

                // Serialize API template
                if (entry.getValue().apiTemplate != null) {
                    ApiTemplate template = entry.getValue().apiTemplate;
                    JsonObject templateObj = new JsonObject();
                    
                    if (template.method != null) templateObj.addProperty("method", template.method);
                    if (template.url != null) templateObj.addProperty("url", template.url);
                    if (template.contentType != null) templateObj.addProperty("content_type", template.contentType);
                    if (template.bodyTemplate != null) templateObj.addProperty("body_template", template.bodyTemplate);

                    if (template.authHeaders != null && !template.authHeaders.isEmpty()) {
                        JsonObject headersObj = new JsonObject();
                        for (Map.Entry<String, String> header : template.authHeaders.entrySet()) {
                            headersObj.addProperty(header.getKey(), header.getValue());
                        }
                        templateObj.add("auth_headers", headersObj);
                    }

                    if (template.requiredParams != null && !template.requiredParams.isEmpty()) {
                        JsonArray paramsArr = new JsonArray();
                        for (String param : template.requiredParams) {
                            paramsArr.add(param);
                        }
                        templateObj.add("required_params", paramsArr);
                    }

                    entryObj.add("api_template", templateObj);
                }

                entries.add(entry.getKey(), entryObj);
            }

            root.add("entries", entries);
            root.addProperty("saved_at", System.currentTimeMillis());

            Files.writeString(cachePath, root.toString(), StandardCharsets.UTF_8);
            logger.debug("[ExplorationCache] 持久化了 %d 个缓存条目", cache.size());
        } catch (IOException e) {
            logger.warn("[ExplorationCache] 持久化缓存失败: %s", e.getMessage());
        }
    }

    private String normalizeKey(String targetApi) {
        if (targetApi == null) return "";
        // Normalize: "POST /api/v1/roles" or "/api/v1/roles"
        String key = targetApi.trim().toUpperCase();
        // If no method prefix, assume it's just a path
        if (!key.matches("^(GET|POST|PUT|DELETE|PATCH|OPTIONS|HEAD)\\s+.*")) {
            key = "GET " + key;
        }
        return key;
    }

    private String str(JsonObject obj, String key) {
        return obj.has(key) && !obj.get(key).isJsonNull() ? obj.get(key).getAsString() : null;
    }

    /**
     * Cached entry containing both UI actions and API template.
     */
    public record CachedEntry(
        List<BrowserAction> actions,
        ApiTemplate apiTemplate,
        long timestamp
    ) {
        /**
         * Check if this entry can be triggered via direct HTTP (has API template).
         */
        public boolean canDirectTrigger() {
            return apiTemplate != null;
        }

        /**
         * Check if this entry can be triggered via UI replay (has actions).
         */
        public boolean canUiReplay() {
            return actions != null && !actions.isEmpty();
        }
    }
}
