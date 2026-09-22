package com.flechazo.apisentinel.config;

import com.flechazo.apisentinel.logging.LeveledLogger;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.attribute.PosixFilePermission;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * Manages login profiles for automatic browser authentication.
 *
 * <p>Profiles are persisted to {@code ~/.api-sentinel/login-profiles.json}.
 * Provides methods to add, remove, find, and list profiles.
 *
 * <p>Thread-safe: all operations are synchronized.
 */
public class LoginProfileManager {

    private static final String CONFIG_DIR = ".api-sentinel";
    private static final String PROFILES_FILE = "login-profiles.json";

    private final LeveledLogger logger;
    private final Path configPath;
    private final List<LoginProfile> profiles = new CopyOnWriteArrayList<>();

    public LoginProfileManager(LeveledLogger logger) {
        this(logger, Paths.get(System.getProperty("user.home"), CONFIG_DIR, PROFILES_FILE));
    }

    /**
     * Create with a custom config path (for testing).
     */
    public LoginProfileManager(LeveledLogger logger, Path configPath) {
        this.logger = logger;
        this.configPath = configPath;
        load();
    }

    /**
     * Get all configured profiles.
     */
    public List<LoginProfile> getAll() {
        return List.copyOf(profiles);
    }

    /**
     * @return the absolute path where profiles are persisted, for display to the user/agent.
     */
    public String getConfigPathString() {
        return configPath.toAbsolutePath().toString();
    }

    /**
     * Find a profile by name.
     *
     * @param name the profile name
     * @return the profile, or empty if not found
     */
    public Optional<LoginProfile> findByName(String name) {
        return profiles.stream()
                .filter(p -> p.name().equals(name))
                .findFirst();
    }

    /**
     * Find a profile that matches the given URL domain.
     *
     * @param url the target URL
     * @return matching profile, or empty if none matches
     */
    public Optional<LoginProfile> findByUrl(String url) {
        if (url == null || url.isEmpty()) return Optional.empty();

        // Extract domain from URL
        String domain = extractDomain(url);
        if (domain == null) return Optional.empty();

        return profiles.stream()
                .filter(p -> {
                    String profileDomain = extractDomain(p.loginUrl());
                    return domain.equals(profileDomain) || domain.endsWith("." + profileDomain);
                })
                .findFirst();
    }

    /**
     * Get the default profile (first one, or empty).
     */
    public Optional<LoginProfile> getDefault() {
        return profiles.isEmpty() ? Optional.empty() : Optional.of(profiles.get(0));
    }

    /**
     * Add a new profile.
     *
     * @param profile the profile to add
     * @return true if added, false if a profile with the same name already exists
     */
    public boolean add(LoginProfile profile) {
        if (findByName(profile.name()).isPresent()) {
            logger.warn("[LoginProfileManager] Profile already exists: %s", profile.name());
            return false;
        }
        profiles.add(profile);
        save();
        logger.info("[LoginProfileManager] Added profile: %s", profile.name());
        return true;
    }

    /**
     * Update an existing profile.
     *
     * @param profile the updated profile
     * @return true if updated, false if not found
     */
    public boolean update(LoginProfile profile) {
        for (int i = 0; i < profiles.size(); i++) {
            if (profiles.get(i).name().equals(profile.name())) {
                profiles.set(i, profile);
                save();
                logger.info("[LoginProfileManager] Updated profile: %s", profile.name());
                return true;
            }
        }
        return false;
    }

    /**
     * Remove a profile by name.
     *
     * @param name the profile name
     * @return true if removed
     */
    public boolean remove(String name) {
        boolean removed = profiles.removeIf(p -> p.name().equals(name));
        if (removed) {
            save();
            logger.info("[LoginProfileManager] Removed profile: %s", name);
        }
        return removed;
    }

    /**
     * Load profiles from disk.
     */
    public void load() {
        profiles.clear();

        if (!Files.exists(configPath)) {
            logger.debug("[LoginProfileManager] No profiles file found at %s", configPath);
            return;
        }

        try {
            String content = Files.readString(configPath, StandardCharsets.UTF_8);
            JsonObject root = JsonParser.parseString(content).getAsJsonObject();

            if (root.has("profiles")) {
                JsonArray arr = root.getAsJsonArray("profiles");
                for (JsonElement el : arr) {
                    try {
                        profiles.add(LoginProfile.fromJson(el.getAsJsonObject()));
                    } catch (Exception e) {
                        logger.warn("[LoginProfileManager] Failed to parse profile: %s", e.getMessage());
                    }
                }
            }

            // Demoted from INFO to DEBUG: the main startup banner already
            // summarizes profile count at the right phase of initialization.
            // Keeping this at INFO caused the "Loaded N profiles" message to
            // appear between the banner and the main init block, breaking
            // the visual grouping of startup logs.
            logger.debug("[LoginProfileManager] Loaded %d profiles from %s", profiles.size(), configPath);
        } catch (Exception e) {
            logger.error("[LoginProfileManager] Failed to load profiles: %s", e.getMessage());
        }
    }

    /**
     * Save profiles to disk.
     *
     * <p>After writing, attempts to restrict the file to owner-only read/write (POSIX 600)
     * since the file may contain plaintext credentials. On non-POSIX filesystems (Windows,
     * some mounted volumes) the permission step is silently skipped and a debug log emitted.
     */
    public void save() {
        try {
            // Ensure directory exists
            Files.createDirectories(configPath.getParent());

            JsonObject root = new JsonObject();
            JsonArray arr = new JsonArray();
            for (LoginProfile profile : profiles) {
                arr.add(profile.toJson());
            }
            root.add("profiles", arr);

            Files.writeString(configPath, root.toString(), StandardCharsets.UTF_8);
            logger.debug("[LoginProfileManager] Saved %d profiles to %s", profiles.size(), configPath);

            // Restrict file to owner-only (credentials are stored in plaintext, so at least
            // make them unreadable by other local users). Silently ignored on non-POSIX fs.
            try {
                Set<PosixFilePermission> ownerOnly = EnumSet.of(
                        PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE);
                Files.setPosixFilePermissions(configPath, ownerOnly);
            } catch (UnsupportedOperationException unsupported) {
                logger.debug("[LoginProfileManager] POSIX permissions not supported on %s (non-POSIX fs)",
                        configPath);
            } catch (IOException permErr) {
                logger.warn("[LoginProfileManager] Failed to set 600 permissions on %s: %s",
                        configPath, permErr.getMessage());
            }
        } catch (IOException e) {
            logger.error("[LoginProfileManager] Failed to save profiles: %s", e.getMessage());
        }
    }

    /**
     * Extract domain from a URL.
     */
    private String extractDomain(String url) {
        if (url == null) return null;
        try {
            int schemeEnd = url.indexOf("://");
            if (schemeEnd < 0) return null;
            int pathStart = url.indexOf('/', schemeEnd + 3);
            String host = pathStart > 0 ? url.substring(schemeEnd + 3, pathStart) : url.substring(schemeEnd + 3);
            // Remove port
            int portIdx = host.indexOf(':');
            return portIdx > 0 ? host.substring(0, portIdx) : host;
        } catch (Exception e) {
            return null;
        }
    }
}
