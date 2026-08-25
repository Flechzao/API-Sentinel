package com.flechazo.apisentinel.matching;

import com.flechazo.apisentinel.config.AppConfig;
import com.flechazo.apisentinel.config.ConfigManager;
import com.flechazo.apisentinel.config.MatchMode;
import com.flechazo.apisentinel.model.ApiEntry;

import java.util.*;

/**
 * Composite match engine that delegates to the appropriate engine based on the configured match mode.
 * <ul>
 *   <li><b>EXACT</b> (default): Trie-based matching with {id} wildcards and /** glob-star support.</li>
 *   <li><b>FUZZY</b>: Aho-Corasick substring matching (searches URL and optionally request body).</li>
 * </ul>
 */
public class CompositeMatchEngine implements MatchEngine {

    private final TrieMatchEngine trieEngine;
    private final FuzzyMatchEngine fuzzyEngine;
    private final ConfigManager configManager;
    private static final int MAX_CACHE_SIZE = 1024;

    private final Map<String, List<ApiEntry>> cache = Collections.synchronizedMap(
        new LinkedHashMap<String, List<ApiEntry>>(256, 0.75f, true) {
            @Override
            protected boolean removeEldestEntry(Map.Entry<String, List<ApiEntry>> eldest) {
                return size() > MAX_CACHE_SIZE;
            }
        }
    );

    public CompositeMatchEngine(TrieMatchEngine trieEngine, FuzzyMatchEngine fuzzyEngine, ConfigManager configManager) {
        this.trieEngine = trieEngine;
        this.fuzzyEngine = fuzzyEngine;
        this.configManager = configManager;
    }

    @Override
    public List<ApiEntry> match(String urlPath, String requestBody) {
        AppConfig config = configManager.getConfig();
        MatchMode mode = config.getMatchMode().normalize();

        // Include body length + hashcode to avoid collisions (e.g. "Aa" vs "BB"
        // share String#hashCode but differ in length).
        String cacheKey = mode == MatchMode.FUZZY
                ? mode.name() + ":" + urlPath + ":" + (requestBody == null ? 0 : requestBody.length())
                  + ":" + Objects.hashCode(requestBody)
                : mode.name() + ":" + urlPath;
        List<ApiEntry> cached = cache.get(cacheKey);
        if (cached != null) {
            return cached;
        }

        List<ApiEntry> result = switch (mode) {
            case EXACT -> trieEngine.matchExact(urlPath);
            case FUZZY -> fuzzyEngine.match(urlPath, config.isCheckWholeRequest() ? requestBody : null);
            default -> trieEngine.matchExact(urlPath); // legacy fallback
        };

        cache.put(cacheKey, result);
        return result;
    }

    @Override
    public void rebuild(Collection<ApiEntry> entries) {
        clearCache();
        trieEngine.rebuild(entries);
        fuzzyEngine.rebuild(entries);
    }

    @Override
    public void addEntry(ApiEntry entry) {
        clearCache();
        trieEngine.addEntry(entry);
        fuzzyEngine.addEntry(entry);
    }

    @Override
    public void removeEntry(String apiPath) {
        clearCache();
        trieEngine.removeEntry(apiPath);
        fuzzyEngine.removeEntry(apiPath);
    }

    public void clearCache() {
        cache.clear();
    }
}
