package com.flechazo.apisentinel.browser;

import com.flechazo.apisentinel.logging.LeveledLogger;
import com.flechazo.apisentinel.ui.I18n;
import com.microsoft.playwright.*;
import com.microsoft.playwright.options.Proxy;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.URL;
import java.nio.file.*;
import java.util.Collections;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.Enumeration;

/**
 * Manages Playwright and Chromium browser lifecycle.
 *
 * <p>Lazy initialization: browser is started on first use, not at construction.
 * Thread-safe: all methods synchronize on the instance lock.
 *
 * <p>Usage:
 * <pre>
 * BrowserManager manager = new BrowserManager(logger);
 * manager.configure(8080, true, null);  // Burp port, headless, no custom chrome
 * Page page = manager.newPage();
 * page.navigate("https://target.com");
 * // ... use page ...
 * manager.close();
 * </pre>
 */
public class BrowserManager {

    private final LeveledLogger logger;
    private final AtomicBoolean running = new AtomicBoolean(false);

    private Playwright playwright;
    private Browser browser;
    private BrowserContext context;

    /** Shared page for session reuse — avoids opening/closing tabs on every tool call. */
    private Page sharedPage;

    private int burpProxyPort = 8080;
    private boolean headless = true;

    /** Check if running in headless mode. */
    public boolean isHeadless() { return headless; }
    private String chromePath = null;

    public BrowserManager(LeveledLogger logger) {
        this.logger = logger;
    }

    /**
     * Configure browser settings. Must be called before first use.
     *
     * @param burpProxyPort Burp proxy port (e.g., 8080)
     * @param headless whether to run in headless mode
     * @param chromePath optional custom Chrome path (null = use Playwright's bundled Chromium)
     */
    public void configure(int burpProxyPort, boolean headless, String chromePath) {
        this.burpProxyPort = burpProxyPort;
        this.headless = headless;
        this.chromePath = chromePath;
    }

    /**
     * Auto-detect system-installed browsers (Chrome, Chromium, Edge).
     * Returns the executable path if found, null otherwise.
     */
    private String detectSystemBrowser() {
        String os = System.getProperty("os.name").toLowerCase();
        String[] candidates;

        if (os.contains("mac")) {
            candidates = new String[]{
                    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
                    "/Applications/Chromium.app/Contents/MacOS/Chromium",
                    "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
                    "/Applications/Brave Browser.app/Contents/MacOS/Brave Browser"
            };
        } else if (os.contains("windows")) {
            String programFiles = System.getenv("ProgramFiles");
            String programFilesX86 = System.getenv("ProgramFiles(x86)");
            String localAppData = System.getenv("LOCALAPPDATA");
            candidates = new String[]{
                    programFiles + "\\Google\\Chrome\\Application\\chrome.exe",
                    programFilesX86 + "\\Google\\Chrome\\Application\\chrome.exe",
                    programFiles + "\\Microsoft\\Edge\\Application\\msedge.exe",
                    programFilesX86 + "\\Microsoft\\Edge\\Application\\msedge.exe",
                    localAppData + "\\Google\\Chrome\\Application\\chrome.exe"
            };
        } else {
            // Linux / Unix
            candidates = new String[]{
                    "/usr/bin/google-chrome",
                    "/usr/bin/google-chrome-stable",
                    "/usr/bin/chromium",
                    "/usr/bin/chromium-browser",
                    "/usr/bin/microsoft-edge",
                    "/usr/bin/microsoft-edge-stable",
                    "/snap/bin/chromium",
                    "/snap/bin/google-chrome"
            };
        }

        for (String path : candidates) {
            if (path != null && Files.exists(Paths.get(path))) {
                logger.debug("[Browser] Auto-detected system browser: %s", path);
                return path;
            }
        }

        logger.debug("[Browser] No system browser detected");
        return null;
    }

    /**
     * Detect Playwright-installed Chromium (via `npx playwright install chromium`).
     * Returns the executable path if found, null otherwise.
     */
    private String detectPlaywrightChromium() {
        String os = System.getProperty("os.name").toLowerCase();
        Path cacheDir = Paths.get(System.getProperty("user.home"), ".cache", "ms-playwright");

        if (!Files.isDirectory(cacheDir)) {
            return null;
        }

        try {
            // Find chromium-* directories (version number varies), use newest
            return Files.list(cacheDir)
                    .filter(p -> p.getFileName().toString().startsWith("chromium-"))
                    .sorted((a, b) -> b.getFileName().toString().compareTo(a.getFileName().toString()))
                    .map(chromiumDir -> {
                        String execName;
                        if (os.contains("mac")) {
                            execName = "chrome-mac/Chromium.app/Contents/MacOS/Chromium";
                        } else if (os.contains("windows")) {
                            execName = "chrome-win\\chrome.exe";
                        } else {
                            execName = "chrome-linux/chrome";
                        }
                        Path execPath = chromiumDir.resolve(execName);
                        return Files.exists(execPath) ? execPath.toString() : null;
                    })
                    .filter(p -> p != null)
                    .findFirst()
                    .orElse(null);
        } catch (Exception e) {
            logger.debug("[Browser] Error checking Playwright cache: %s", e.getMessage());
            return null;
        }
    }

    /**
     * Start the browser if not already running. Thread-safe.
     *
     * @throws BrowserException if browser cannot be started
     */
    public synchronized void ensureStarted() {
        if (running.get()) return;

        try {
            logger.debug("[Browser] Starting Playwright + Chromium (proxy=127.0.0.1:%d, headless=%s)",
                    burpProxyPort, headless);

            // Burp extensions use a custom classloader, so Playwright's
            // Thread.currentThread().getContextClassLoader().getResource("driver/...")
            // fails to find the bundled driver. Pre-extract it and point Playwright
            // at the extracted directory via the playwright.cli.dir system property.
            preinstallDriver();

            playwright = Playwright.create();

            BrowserType.LaunchOptions options = new BrowserType.LaunchOptions()
                    .setHeadless(headless)
                    .setProxy(new Proxy("http://127.0.0.1:" + burpProxyPort));

            // Priority: user config > Playwright Chromium > system browser > Playwright default
            String browserPath = chromePath;
            if (browserPath == null || browserPath.isEmpty()) {
                browserPath = detectPlaywrightChromium();
            }
            if (browserPath == null || browserPath.isEmpty()) {
                browserPath = detectSystemBrowser();
            }

            if (browserPath != null && !browserPath.isEmpty()) {
                options.setChannel("chrome");
                options.setExecutablePath(Path.of(browserPath));
                logger.info("[Browser] Using browser: %s", browserPath);
            }

            browser = playwright.chromium().launch(options);

            // Create a context with reasonable defaults for security testing
            context = browser.newContext(new Browser.NewContextOptions()
                    .setIgnoreHTTPSErrors(true)  // Target may have self-signed certs
                    .setViewportSize(1920, 1080));

            running.set(true);
            logger.info("[Browser] Chromium started successfully");

        } catch (Exception e) {
            String msg = e.getMessage() != null ? e.getMessage() : "";
            // Playwright browser not installed — provide actionable guidance
            // for JAR users (most Burp users don't have Gradle/Maven)
            if (msg.contains("driver") || msg.contains("Driver") || msg.contains("executable")
                    || e.getClass().getSimpleName().contains("Playwright")) {
                String guidance = "═══════ Playwright Browser Not Installed ═══════\n"
                        + "Browser analysis requires a standalone Chromium (does not affect your system Chrome).\n"
                        + "Install via one of these methods:\n\n"
                        + "[Option 1] Auto install (recommended, ~80MB)\n"
                        + "  Download playwright-cli.jar from:\n"
                        + "  https://github.com/nicholasgasior/playwright-java-cli/releases\n"
                        + "  Then run: java -jar playwright-cli.jar install chromium\n\n"
                        + "[Option 2] Use system Chrome\n"
                        + "  In API Sentinel Settings, set Chrome Path to:\n"
                        + "  macOS:  /Applications/Google Chrome.app/Contents/MacOS/Google Chrome\n"
                        + "  Windows: C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe\n\n"
                        + "[Option 3] Build from source\n"
                        + "  ./gradlew installChromium\n"
                        + "═══════════════════════════════════════";
                logger.error("[Browser] %s", guidance);
            }
            logger.error("[Browser] Start failed: %s", msg);
            close();  // Cleanup partial state
            throw new BrowserException("Failed to start browser: " + msg, e);
        }
    }

    /**
     * Create a new page in the browser context.
     *
     * @return a new Page instance
     * @throws BrowserException if browser is not running
     */
    public synchronized Page newPage() {
        ensureStarted();
        if (context == null) {
            throw new BrowserException("Browser context not initialized");
        }
        return context.newPage();
    }

    /**
     * Get or create a shared page for session reuse.
     *
     * <p>Unlike {@link #newPage()}, this returns the same page across multiple
     * calls within a session. This avoids the annoying UX of browser tabs
     * popping open and closing on every tool call (especially visible in
     * non-headless mode).
     *
     * <p>Cookie/session state is shared via the BrowserContext, so login
     * performed on this page persists across subsequent tool calls.
     *
     * @return the shared page (created on first call, reused thereafter)
     */
    public synchronized Page getSharedPage() {
        ensureStarted();
        if (context == null) {
            throw new BrowserException("Browser context not initialized");
        }
        if (sharedPage == null || sharedPage.isClosed()) {
            sharedPage = context.newPage();
            logger.debug("[Browser] Create shared page");
        }
        return sharedPage;
    }

    /**
     * Check if the given page is the shared page (without creating a new one).
     */
    public synchronized boolean isSharedPage(Page page) {
        return page != null && page == sharedPage && !page.isClosed();
    }

    /**
     * Release (close) the shared page. Called when the session ends
     * or a fresh page is needed.
     */
    public synchronized void releaseSharedPage() {
        if (sharedPage != null && !sharedPage.isClosed()) {
            try {
                sharedPage.close();
            } catch (Exception ignored) {}
            logger.debug("[Browser] Release shared page");
        }
        sharedPage = null;
    }

    /**
     * Check if the browser is currently running.
     */
    public boolean isRunning() {
        return running.get();
    }

    /**
     * Lightweight prerequisite check — verifies the Playwright driver has
     * been extracted without actually launching a browser. Returns a status
     * string for UI display.
     */
    public static String checkPrerequisites() {
        String cliDir = System.getProperty("playwright.cli.dir");
        if (cliDir != null && java.nio.file.Files.isDirectory(java.nio.file.Paths.get(cliDir))) {
            return I18n.get("empty_browser_ready");
        }
        // Check the default extraction path
        String platformDir = platformDir();
        java.nio.file.Path defaultPath = java.nio.file.Paths.get(
                System.getProperty("user.home"), ".api-sentinel", "playwright-driver", platformDir);
        if (java.nio.file.Files.isDirectory(defaultPath)) {
            return I18n.get("empty_browser_ready");
        }
        return I18n.get("empty_browser_not_installed");
    }

    /**
     * Close the browser and release all resources.
     */
    public synchronized void close() {
        if (!running.get() && playwright == null) return;

        try {
            releaseSharedPage();
            if (context != null) {
                context.close();
                context = null;
            }
            if (browser != null) {
                browser.close();
                browser = null;
            }
            if (playwright != null) {
                playwright.close();
                playwright = null;
            }
            running.set(false);
            logger.debug("[Browser] Chromium closed");
        } catch (Exception e) {
            logger.warn("[Browser] Error during close: %s", e.getMessage());
        }
    }

    /**
     * Get the Burp proxy port.
     */
    public int getBurpProxyPort() {
        return burpProxyPort;
    }

    /**
     * Pre-extract the Playwright driver from the extension JAR to a temp directory.
     *
     * <p>Playwright's DriverJar uses Thread.currentThread().getContextClassLoader()
     * to find driver resources, which fails in Burp's extension classloader hierarchy.
     * This method extracts the driver using the extension's own classloader, then
     * sets the "playwright.cli.dir" system property so Playwright uses the
     * pre-extracted driver (PreinstalledDriver) instead of trying to find it itself.
     */
    private void preinstallDriver() {
        // Skip if already set (e.g., from a previous call or manual configuration)
        if (System.getProperty("playwright.cli.dir") != null) {
            logger.debug("[Browser] playwright.cli.dir set, skip driver extraction");
            return;
        }

        try {
            String platformDir = platformDir();
            String resourcePrefix = "driver/" + platformDir + "/";

            // Use THIS class's classloader (extension classloader, not context CL)
            ClassLoader extCl = BrowserManager.class.getClassLoader();
            URL testUrl = extCl.getResource(resourcePrefix);
            if (testUrl == null) {
                logger.warn("[Browser] driver/%s not found in extension classloader, trying context CL", platformDir);
                // Fall back: maybe context CL works after all
                testUrl = Thread.currentThread().getContextClassLoader().getResource(resourcePrefix);
            }
            if (testUrl == null) {
                logger.warn("[Browser] driver resource not found, fallback to Playwright default");
                return;
            }

            // Extract to a persistent temp directory (not system temp — survives reboots
            // so we don't re-extract 125MB every time)
            Path driverHome = Paths.get(System.getProperty("user.home"),
                    ".api-sentinel", "playwright-driver", platformDir);
            Path nodePath = driverHome.resolve(
                    System.getProperty("os.name").toLowerCase().contains("windows") ? "node.exe" : "node");

            if (Files.exists(nodePath)) {
                logger.debug("[Browser] driver cached at %s", driverHome);
                System.setProperty("playwright.cli.dir", driverHome.toString());
                return;
            }

            logger.debug("[Browser] Extracting Playwright driver to %s ...", driverHome);
            Files.createDirectories(driverHome);

            // If the resource is inside a JAR, use FileSystem to walk it
            URI driverUri = testUrl.toURI();
            if ("jar".equals(driverUri.getScheme())) {
                // jar:file:/path/to/ext.jar!/driver/mac-arm64/
                String jarPath = driverUri.toString().split("!/")[0] + "!/";
                URI jarUri = new URI(jarPath);
                try (FileSystem fs = FileSystems.newFileSystem(jarUri, Collections.emptyMap())) {
                    Path srcRoot = fs.getPath("/" + resourcePrefix);
                    extractDirectory(srcRoot, driverHome);
                } catch (FileSystemAlreadyExistsException e) {
                    // FileSystem already open (e.g., second call) — use it directly
                    FileSystem fs = FileSystems.getFileSystem(jarUri);
                    Path srcRoot = fs.getPath("/" + resourcePrefix);
                    extractDirectory(srcRoot, driverHome);
                }
            } else {
                // Running from exploded classes (IDE mode)
                Path srcRoot = Paths.get(driverUri);
                extractDirectory(srcRoot, driverHome);
            }

            // Ensure node binary is executable
            if (Files.exists(nodePath)) {
                nodePath.toFile().setExecutable(true, false);
            }

            System.setProperty("playwright.cli.dir", driverHome.toString());
            logger.debug("[Browser] driver extraction complete");

        } catch (Exception e) {
            logger.warn("[Browser] driver pre-extraction failed, fallback to Playwright default", e.getMessage());
        }
    }

    private void extractDirectory(Path src, Path dest) throws IOException {
        Files.walk(src).forEach(fromPath -> {
            try {
                Path relative = src.relativize(fromPath);
                Path toPath = dest.resolve(relative.toString());
                if (Files.isDirectory(fromPath)) {
                    Files.createDirectories(toPath);
                } else {
                    Files.copy(fromPath, toPath, StandardCopyOption.REPLACE_EXISTING);
                    // Preserve executable permission
                    String name = fromPath.getFileName().toString();
                    if (name.endsWith(".sh") || name.endsWith(".exe") || !name.contains(".")) {
                        toPath.toFile().setExecutable(true, false);
                    }
                }
            } catch (IOException e) {
                throw new RuntimeException("Failed to extract driver: " + fromPath, e);
            }
        });
    }

    private static String platformDir() {
        String os = System.getProperty("os.name").toLowerCase();
        String arch = System.getProperty("os.arch").toLowerCase();
        if (os.contains("windows")) return "win32_x64";
        if (os.contains("mac")) return arch.equals("aarch64") ? "mac-arm64" : "mac";
        return arch.equals("aarch64") ? "linux-arm64" : "linux";
    }

    /**
     * Exception thrown when browser operations fail.
     */
    public static class BrowserException extends RuntimeException {
        public BrowserException(String message) {
            super(message);
        }

        public BrowserException(String message, Throwable cause) {
            super(message, cause);
        }
    }
}
