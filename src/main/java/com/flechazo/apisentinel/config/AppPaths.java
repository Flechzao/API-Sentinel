package com.flechazo.apisentinel.config;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.attribute.PosixFileAttributeView;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;

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
                // P1-5 hardening: create with 700 (owner-only) rather than
                // the umask-inherited 755. The directory holds every
                // secret the plugin knows (API keys, captured cookies,
                // auth sessions, learned rules), so a group/other-readable
                // directory would leak them to any local user on a
                // shared box. The pre-P1-5 behaviour (755 on Linux /
                // ACL-inherited on macOS) left everything world-readable.
                boolean created = false;
                if (!Files.exists(dir)) {
                    try {
                        Files.createDirectory(dir,
                                PosixFilePermissions.asFileAttribute(
                                        PosixFilePermissions.fromString("rwx------")));
                        created = true;
                    } catch (UnsupportedOperationException ignored) {
                        // Non-POSIX FS (Windows) — fall through to the
                        // regular createDirectories path and rely on
                        // NTFS ACLs.
                        Files.createDirectories(dir);
                        created = true;
                    }
                }
                if (!created) {
                    // Directory already exists from a pre-P1-5 install;
                    // tighten it now so existing users get the fix too.
                    tightenDirectoryPermissions(dir);
                }
            } catch (IOException ignored) {
                // best-effort; callers handle read/write failures individually
            }
            configDir = dir;
            return dir;
        }
    }

    /** Best-effort chmod 700 on an existing directory. Logged at WARN
     *  (not thrown) so a read-only install doesn't break the plugin. */
    public static void tightenDirectoryPermissions(Path dir) {
        try {
            java.util.Set<PosixFilePermission> perms = PosixFilePermissions.fromString("rwx------");
            PosixFileAttributeView view = Files.getFileAttributeView(dir, PosixFileAttributeView.class);
            if (view != null) {
                java.util.Set<PosixFilePermission> current = view.readAttributes().permissions();
                if (!current.equals(perms)) view.setPermissions(perms);
            }
        } catch (UnsupportedOperationException | IOException ignored) {
            // non-POSIX or unfixable; nothing to do
        }
    }

    /** P1-5: write a file with 600 (owner-only) permissions in a single
     *  step, so secrets written via this helper are never briefly
     *  readable by group/other before a follow-up chmod tightens them.
     *  On non-POSIX file systems (Windows) the ACL-inherited mode is
     *  kept — there's no equivalent of chmod there.
     *
     *  <p>Use this for every file that may contain a secret: ai-config
     *  (API keys), data.json (captured cookies/credentials),
     *  chat-history (conversation transcripts), sensitive-rules, and
     *  the learned-rules / false-positives caches (which can carry
     *  payload echoes). */
    public static void writePrivate(Path file, String content) throws IOException {
        try {
            if (!Files.exists(file)) {
                Files.createFile(file,
                        PosixFilePermissions.asFileAttribute(
                                PosixFilePermissions.fromString("rw-------")));
            } else {
                // Existing file from a pre-P1-5 install — tighten before
                // the write so the new content never lands with loose
                // perms even for a brief window.
                PosixFileAttributeView view = Files.getFileAttributeView(file, PosixFileAttributeView.class);
                if (view != null) {
                    java.util.Set<PosixFilePermission> want = PosixFilePermissions.fromString("rw-------");
                    if (!view.readAttributes().permissions().equals(want)) {
                        view.setPermissions(want);
                    }
                }
            }
            Files.writeString(file, content);
        } catch (UnsupportedOperationException e) {
            // Non-POSIX FS — fall back to a regular write; the user is
            // on Windows and relies on NTFS ACLs.
            Files.writeString(file, content);
        }
    }

    public static Path resolve(String name) { return configDir().resolve(name); }

    /** P3-5: test-only reset. Clears the cached configDir so the next
     *  call re-reads the environment. Without this, tests that set
     *  {@code API_SENTINEL_HOME} via system property see the FIRST
     *  access's value forever (double-checked locking caches it).
     *  Call this in a {@code @BeforeEach} or {@code @AfterEach} when
     *  a test needs a specific config directory. */
    public static void resetForTest() {
        synchronized (AppPaths.class) {
            configDir = null;
        }
    }

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
