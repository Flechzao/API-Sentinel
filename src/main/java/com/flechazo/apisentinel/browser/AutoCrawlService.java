package com.flechazo.apisentinel.browser;

import com.flechazo.apisentinel.ai.provider.LlmProvider;
import com.flechazo.apisentinel.browser.BrowserLogin.LoginResult;
import com.flechazo.apisentinel.browser.BrowserService.BrowserAction;
import com.flechazo.apisentinel.browser.BrowserService.DiscoveryResult;
import com.flechazo.apisentinel.browser.ExplorationEngine.ExploreResult;
import com.flechazo.apisentinel.config.CrawlConfig;
import com.flechazo.apisentinel.config.LoginProfile;
import com.flechazo.apisentinel.config.LoginProfileManager;
import com.flechazo.apisentinel.logging.LeveledLogger;
import com.flechazo.apisentinel.repository.ApiRepository;

import java.util.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Consumer;

/**
 * Auto-crawl service: orchestrates login → discover → explore → register
 * for full-site API scanning.
 *
 * <p>Workflow:
 * <ol>
 *   <li>browser_login → get authenticated session</li>
 *   <li>browser_discover → find all frontend routes + static APIs</li>
 *   <li>For each undiscovered API → browser_explore to find trigger path</li>
 *   <li>register_discovered_apis → add to analysis queue</li>
 * </ol>
 *
 * <p>Supports progress reporting and interruption.
 */
public class AutoCrawlService {

    private final LeveledLogger logger;
    private final BrowserService browserService;
    private final LoginProfileManager profileManager;
    private final LlmProvider llmProvider;
    private final ApiRepository apiRepository;

    /** Whether a crawl is currently running. */
    private final AtomicBoolean running = new AtomicBoolean(false);

    /** Set to true to request interruption. */
    private final AtomicBoolean interrupted = new AtomicBoolean(false);

    /** Progress callback. */
    private volatile Consumer<CrawlProgress> progressCallback;

    public AutoCrawlService(LeveledLogger logger, BrowserService browserService,
                            LoginProfileManager profileManager, LlmProvider llmProvider,
                            ApiRepository apiRepository) {
        this.logger = logger;
        this.browserService = browserService;
        this.profileManager = profileManager;
        this.llmProvider = llmProvider;
        this.apiRepository = apiRepository;
    }

    /**
     * Set a progress callback.
     */
    public void setProgressCallback(Consumer<CrawlProgress> callback) {
        this.progressCallback = callback;
    }

    /**
     * Check if a crawl is currently running.
     */
    public boolean isRunning() {
        return running.get();
    }

    /**
     * Request interruption of the current crawl.
     */
    public void interrupt() {
        interrupted.set(true);
        logger.info("[AutoCrawl] 收到中断请求");
    }

    /**
     * Run a full auto-crawl.
     *
     * @param config crawl configuration
     * @return crawl result summary
     */
    public CrawlResult crawl(CrawlConfig config) {
        if (!running.compareAndSet(false, true)) {
            return CrawlResult.failure("已有爬取任务正在运行");
        }
        interrupted.set(false);

        logger.info("[AutoCrawl] 开始全站爬取: %s", config.startUrl());
        reportProgress("started", "开始全站爬取", 0, 0, 0, 0);

        try {
            // Phase 1: Login
            reportProgress("login", "正在登录...", 0, 0, 0, 0);
            LoginResult loginResult = performLogin(config);
            if (!loginResult.success()) {
                return CrawlResult.failure("登录失败: " + loginResult.message());
            }
            logger.info("[AutoCrawl] 登录成功 (%d 个 cookie)", loginResult.cookies().size());

            if (interrupted.get()) return CrawlResult.interrupted();

            // Phase 2: Discover routes and APIs
            reportProgress("discover", "正在发现路由和 API...", 0, 0, 0, 0);
            DiscoveryResult discoveryResult = browserService.discoverApis(
                    config.startUrl(), Math.min(config.exploreDepth(), 3));

            List<DiscoveredApi> staticApis = discoveryResult.apis();
            List<String> routes = extractRoutePaths(discoveryResult);
            logger.info("[AutoCrawl] 发现 %d 个静态 API, %d 个前端路由",
                    staticApis.size(), routes.size());

            reportProgress("discover_done",
                    String.format("发现 %d 个 API, %d 个路由", staticApis.size(), routes.size()),
                    staticApis.size(), 0, routes.size(), 0);

            if (interrupted.get()) return CrawlResult.interrupted();

            // Phase 3: Filter APIs to explore
            List<DiscoveredApi> apisToExplore = filterApisToExplore(staticApis, config);
            logger.info("[AutoCrawl] 需要探索的 API: %d (排除 %d 个已发现/已排除的)",
                    apisToExplore.size(), staticApis.size() - apisToExplore.size());

            // Phase 4: Explore each API
            ExplorationEngine engine = new ExplorationEngine(
                    logger, browserService.getBrowserManager(), llmProvider);

            AtomicInteger exploredCount = new AtomicInteger(0);
            AtomicInteger successCount = new AtomicInteger(0);
            Map<String, List<BrowserAction>> exploredPaths = new LinkedHashMap<>();

            for (int i = 0; i < apisToExplore.size(); i++) {
                if (interrupted.get()) {
                    logger.info("[AutoCrawl] 被中断，已探索 %d/%d", i, apisToExplore.size());
                    break;
                }

                DiscoveredApi api = apisToExplore.get(i);
                String targetApi = api.method() + " " + api.path();

                reportProgress("explore",
                        String.format("探索 %s (%d/%d)", targetApi, i + 1, apisToExplore.size()),
                        staticApis.size(), exploredCount.get(), routes.size(), successCount.get());

                logger.debug("[AutoCrawl] 探索 [%d/%d]: %s", i + 1, apisToExplore.size(), targetApi);

                try {
                    ExploreResult result = engine.explore(
                            config.startUrl(), targetApi, config.exploreDepth(), List.of());

                    exploredCount.incrementAndGet();
                    if (result.success()) {
                        successCount.incrementAndGet();
                        exploredPaths.put(targetApi, result.actionSequence());
                        logger.debug("[AutoCrawl] ✓ %s 触发成功 (%d 步)",
                                targetApi, result.actionSequence().size());
                    } else {
                        logger.debug("[AutoCrawl] ✗ %s 未触发: %s",
                                targetApi, result.message());
                    }
                } catch (Exception e) {
                    logger.warn("[AutoCrawl] 探索 %s 异常: %s", targetApi, e.getMessage());
                }
            }

            // Phase 5: Register discovered APIs
            int registered = registerApis(staticApis);

            reportProgress("done", "爬取完成",
                    staticApis.size(), exploredCount.get(), routes.size(), successCount.get());

            String summary = String.format(
                    "爬取完成: 发现 %d 个 API, 探索 %d 个 (成功 %d), 注册 %d 个新 API",
                    staticApis.size(), exploredCount.get(), successCount.get(), registered);

            logger.info("[AutoCrawl] %s", summary);

            return new CrawlResult(
                    true,
                    summary,
                    staticApis.size(),
                    exploredCount.get(),
                    successCount.get(),
                    registered,
                    routes.size(),
                    exploredPaths,
                    interrupted.get()
            );

        } catch (Exception e) {
            logger.error("[AutoCrawl] 爬取异常: %s", e.getMessage());
            return CrawlResult.failure("爬取异常: " + e.getMessage());
        } finally {
            running.set(false);
        }
    }

    /**
     * Perform login using the configured profile.
     */
    private LoginResult performLogin(CrawlConfig config) {
        LoginProfile profile = null;

        // Find profile by name or by URL
        if (config.profileName() != null) {
            profile = profileManager.findByName(config.profileName()).orElse(null);
        }
        if (profile == null) {
            profile = profileManager.findByUrl(config.startUrl()).orElse(null);
        }
        if (profile == null) {
            profile = profileManager.getDefault().orElse(null);
        }

        if (profile == null) {
            // No profile — skip login, proceed without auth
            logger.warn("[AutoCrawl] 未找到登录配置，跳过登录步骤");
            return LoginResult.success("", List.of(), config.startUrl());
        }

        BrowserLogin login = new BrowserLogin(logger, browserService.getBrowserManager());
        return login.login(profile);
    }

    /**
     * Extract route paths from discovery result.
     */
    private List<String> extractRoutePaths(DiscoveryResult result) {
        // Routes are embedded in internal URLs
        List<String> routes = new ArrayList<>();
        for (String url : result.internalUrls()) {
            if (url.startsWith("/")) {
                routes.add(url);
            }
        }
        return routes;
    }

    /**
     * Filter APIs that need exploration (exclude already-known, static, excluded).
     */
    private List<DiscoveredApi> filterApisToExplore(List<DiscoveredApi> apis, CrawlConfig config) {
        List<DiscoveredApi> filtered = new ArrayList<>();

        for (DiscoveredApi api : apis) {
            // Skip excluded patterns
            if (config.isExcluded(api.path())) continue;

            // Skip already in repository (if configured)
            if (config.skipDiscovered() && apiRepository != null) {
                if (apiRepository.findByMethodAndPath(api.method(), api.path()).isPresent()) {
                    continue;
                }
            }

            // Skip static file paths
            if (api.path().matches(".*\\.(css|js|png|jpg|svg|ico|woff|ttf|json)$")) continue;

            filtered.add(api);
        }

        return filtered;
    }

    /**
     * Register all discovered APIs to the repository.
     */
    private int registerApis(List<DiscoveredApi> apis) {
        if (apiRepository == null) return 0;

        int registered = 0;
        for (DiscoveredApi api : apis) {
            if (apiRepository.findByMethodAndPath(api.method(), api.path()).isEmpty()) {
                apiRepository.add(api.toApiEntry(""));
                registered++;
            }
        }

        logger.info("[AutoCrawl] 注册了 %d 个新 API 到仓库", registered);
        return registered;
    }

    /**
     * Report progress to callback.
     */
    private void reportProgress(String phase, String message,
                                int totalApis, int exploredApis,
                                int totalRoutes, int successApis) {
        if (progressCallback != null) {
            progressCallback.accept(new CrawlProgress(
                    phase, message, totalApis, exploredApis, totalRoutes, successApis));
        }
    }

    // ========== Result Types ==========

    /**
     * Progress update during crawl.
     */
    public record CrawlProgress(
            String phase,
            String message,
            int totalApis,
            int exploredApis,
            int totalRoutes,
            int successApis
    ) {}

    /**
     * Final result of an auto-crawl.
     *
     * @param success         whether the crawl completed (or was interrupted)
     * @param summary         human-readable summary
     * @param totalApis       total APIs discovered
     * @param exploredApis    APIs that were explored (attempted to trigger)
     * @param successApis     APIs successfully triggered
     * @param registeredApis  new APIs registered to repository
     * @param totalRoutes     frontend routes found
     * @param exploredPaths   cached action sequences for triggered APIs
     * @param wasInterrupted  whether the crawl was interrupted by user
     */
    public record CrawlResult(
            boolean success,
            String summary,
            int totalApis,
            int exploredApis,
            int successApis,
            int registeredApis,
            int totalRoutes,
            Map<String, List<BrowserAction>> exploredPaths,
            boolean wasInterrupted
    ) {
        public static CrawlResult failure(String message) {
            return new CrawlResult(false, message, 0, 0, 0, 0, 0, Map.of(), false);
        }

        public static CrawlResult interrupted() {
            return new CrawlResult(false, "爬取被用户中断", 0, 0, 0, 0, 0, Map.of(), true);
        }
    }
}
