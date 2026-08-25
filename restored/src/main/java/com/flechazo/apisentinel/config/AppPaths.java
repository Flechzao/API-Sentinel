package com.flechazo.apisentinel.config;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

/**
 * Centralizes all on-disk path resolution for API Sentinel.
 *
 * <p>Industry best practice: a user-level config dir by default
 * ({@code ~/.api-sentinel/}), overridable via the {@code API_SENTINEL_HOME}
 * environment variable or the {@code api-sentinel.home} system property for
 * portability / multi-environment isolation. All config + data files derive
 * from this single root, so a fresh clone / shared jar never carries the
 * author's personal data — every user's data lives under their own root.
 *
 * <p>The root is created lazily on first access (discoverability: a new user
 * sees {@code ~/.api-sentinel/} appear as soon as the extension loads).
 */
public final class AppPaths {

    private static final String HOME_ENV = "API_SENTINEL_HOME";
    private static final String HOME_PROP = "api-sentinel.home";
    private static final String DEFAULT_DIR_NAME = ".api-sentinel";

    private static volatile Path configDir;

    private AppPaths() {}

    /** The configured data root (override wins; else ~/.api-sentinel). Created if missing. */
    public static Path configDir() {
        Path d = configDir;
        if (d != null) return d;
        synchronized (AppPaths.class) {
            if (configDir != null) return configDir;
            String override = System.getenv(HOME_ENV);
            if (override == null || override.isBlank()) {
                override = System.getProperty(HOME_PROP);
            }
            Path dir;
            if (override != null && !override.isBlank()) {
                dir = Paths.get(override);
            } else {
                dir = Paths.get(System.getProperty("user.home"), DEFAULT_DIR_NAME);
            }
            try {
                Files.createDirectories(dir);
            } catch (IOException ignored) {
                // best-effort; callers handle read/write failures individually
            }
            configDir = dir;
            return dir;
        }
    }

    public static Path resolve(String name) { return configDir().resolve(name); }

    public static Path dataFile() { return resolve("data.json"); }
    public static Path configFile() { return resolve("config.json"); }
    public static Path aiConfigFile() { return resolve("ai-config.json"); }
    public static Path chatHistoryFile() { return resolve("chat-history.json"); }
    public static Path learnedRulesFile() { return resolve("learned-rules.json"); }
    public static Path falsePositivesFile() { return resolve("false-positives.json"); }
    public static Path codeIndexFile() { return resolve("code-index.json"); }
    public static Path sensitiveRulesFile() { return resolve("sensitive-rules.json"); }
    public static Path sinkMapFile() { return resolve("sink-map.json"); }
    public static Path reportsDir() { return resolve("reports"); }
    public static Path htmlReportsDir() { return reportsDir().resolve("html"); }
}
