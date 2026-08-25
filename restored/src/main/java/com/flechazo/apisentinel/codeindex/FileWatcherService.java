package com.flechazo.apisentinel.codeindex;

import com.flechazo.apisentinel.config.CodeRepo;
import com.flechazo.apisentinel.logging.LeveledLogger;

import java.io.IOException;
import java.nio.file.*;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.*;
import java.util.concurrent.*;

/** 文件监听服务——监听已索引代码仓库的文件变更，检测到变更时触发增量重新索引。 */
public class FileWatcherService {

    private static final long DEBOUNCE_MS = 5000;
    private static final Set<String> WATCHED_EXTENSIONS = Set.of(
            ".java", ".kt", ".py", ".js", ".ts", ".go");

    private final CodeIndexService codeIndexService;
    private final List<CodeRepo> repos;
    private final LeveledLogger logger;
    private final ScheduledExecutorService debounceExecutor;
    private final Map<String, ScheduledFuture<?>> pendingReindex = new ConcurrentHashMap<>();

    private volatile WatchService watchService;
    private volatile Thread watcherThread;
    private volatile boolean running;

    public FileWatcherService(CodeIndexService codeIndexService,
                              List<CodeRepo> repos,
                              LeveledLogger logger) {
        this.codeIndexService = codeIndexService;
        this.repos = repos != null ? repos : List.of();
        this.logger = logger;
        this.debounceExecutor = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "api-sentinel-file-watcher-debounce");
            t.setDaemon(true);
            return t;
        });
    }

    public void start() {
        if (running || repos.isEmpty()) return;
        try {
            watchService = FileSystems.getDefault().newWatchService();
        } catch (IOException e) {
            logger.error("[FileWatcher] 无法创建 WatchService: %s", e.getMessage());
            return;
        }

        for (CodeRepo repo : repos) {
            registerRepoRecursive(repo);
        }

        running = true;
        watcherThread = new Thread(this::pollLoop, "api-sentinel-file-watcher");
        watcherThread.setDaemon(true);
        watcherThread.start();
        logger.info("[FileWatcher] 已启动，监控 %d 个仓库", repos.size());
    }

    public void shutdown() {
        running = false;
        if (watchService != null) {
            try { watchService.close(); } catch (IOException ignored) {}
        }
        if (watcherThread != null) {
            watcherThread.interrupt();
        }
        debounceExecutor.shutdownNow();
        logger.info("[FileWatcher] 已停止");
    }

    public boolean isRunning() {
        return running;
    }

    private void pollLoop() {
        while (running) {
            WatchKey key;
            try {
                key = watchService.take();
            } catch (InterruptedException | ClosedWatchServiceException e) {
                break;
            }

            Path dir = (Path) key.watchable();
            for (WatchEvent<?> event : key.pollEvents()) {
                WatchEvent.Kind<?> kind = event.kind();
                if (kind == StandardWatchEventKinds.OVERFLOW) continue;

                Path changed = dir.resolve((Path) event.context());
                String fileName = changed.getFileName().toString().toLowerCase();

                if (kind == StandardWatchEventKinds.ENTRY_CREATE && Files.isDirectory(changed)) {
                    registerDirectory(changed);
                    continue;
                }

                if (!isWatchedFile(fileName)) continue;

                CodeRepo affectedRepo = findRepoForPath(changed);
                if (affectedRepo != null) {
                    scheduleReindex(affectedRepo);
                }
            }

            boolean valid = key.reset();
            if (!valid) break;
        }
    }

    private void scheduleReindex(CodeRepo repo) {
        String repoName = repo.getName();
        ScheduledFuture<?> existing = pendingReindex.get(repoName);
        if (existing != null) {
            existing.cancel(false);
        }
        ScheduledFuture<?> future = debounceExecutor.schedule(() -> {
            pendingReindex.remove(repoName);
            logger.info("[FileWatcher] 检测到变更，重新索引: %s", repoName);
            try {
                codeIndexService.indexRepo(repo, true);
            } catch (Exception e) {
                logger.error("[FileWatcher] 重新索引失败 [%s]: %s", repoName, e.getMessage());
            }
        }, DEBOUNCE_MS, TimeUnit.MILLISECONDS);
        pendingReindex.put(repoName, future);
    }

    private void registerRepoRecursive(CodeRepo repo) {
        Path root;
        try {
            root = Path.of(repo.getPath());
        } catch (Exception e) {
            return;
        }
        if (!Files.isDirectory(root)) return;

        try {
            Files.walkFileTree(root, new SimpleFileVisitor<>() {
                @Override
                public FileVisitResult preVisitDirectory(Path dir, BasicFileAttributes attrs) {
                    String dirName = dir.getFileName() != null ? dir.getFileName().toString() : "";
                    if (Set.of("node_modules", ".git", "build", "target", "dist").contains(dirName)) {
                        return FileVisitResult.SKIP_SUBTREE;
                    }
                    registerDirectory(dir);
                    return FileVisitResult.CONTINUE;
                }
            });
        } catch (IOException e) {
            logger.debug("[FileWatcher] 注册目录失败 [%s]: %s", repo.getName(), e.getMessage());
        }
    }

    private void registerDirectory(Path dir) {
        try {
            dir.register(watchService,
                    StandardWatchEventKinds.ENTRY_CREATE,
                    StandardWatchEventKinds.ENTRY_MODIFY,
                    StandardWatchEventKinds.ENTRY_DELETE);
        } catch (IOException ignored) {}
    }

    private CodeRepo findRepoForPath(Path file) {
        for (CodeRepo repo : repos) {
            try {
                Path root = Path.of(repo.getPath());
                if (file.startsWith(root)) return repo;
            } catch (Exception ignored) {}
        }
        return null;
    }

    private boolean isWatchedFile(String fileName) {
        for (String ext : WATCHED_EXTENSIONS) {
            if (fileName.endsWith(ext)) return true;
        }
        return false;
    }
}
