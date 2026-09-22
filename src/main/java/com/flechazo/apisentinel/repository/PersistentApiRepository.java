package com.flechazo.apisentinel.repository;

import com.flechazo.apisentinel.config.AppPaths;
import com.flechazo.apisentinel.logging.LeveledLogger;
import com.flechazo.apisentinel.model.ApiEntry;
import com.flechazo.apisentinel.model.ApiStatus;
import com.flechazo.apisentinel.model.VulnType;
import com.flechazo.apisentinel.util.JsonUtils;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.Collection;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;

public class PersistentApiRepository implements ApiRepository {

    private final InMemoryApiRepository delegate;
    private final Path dataFilePath;
    private final LeveledLogger logger;
    private final AtomicBoolean dirty = new AtomicBoolean(false);
    private final ScheduledExecutorService scheduler;

    public PersistentApiRepository(InMemoryApiRepository delegate, Path dataFilePath, LeveledLogger logger) {
        this.delegate = delegate;
        this.dataFilePath = dataFilePath;
        this.logger = logger;
        this.scheduler = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "api-sentinel-persistence");
            t.setDaemon(true);
            return t;
        });
        scheduler.scheduleAtFixedRate(this::flushIfDirty, 30, 30, TimeUnit.SECONDS);
    }

    @Override
    public void markDirty() {
        dirty.set(true);
    }

    private void flushIfDirty() {
        if (dirty.compareAndSet(true, false)) {
            if (!trySave()) {
                // P0-12 hardening: pre-P0-12, compareAndSet(true, false)
                // ran BEFORE save() so a save failure left dirty=false
                // with no retry scheduled — the in-memory state drifted
                // away from the on-disk state silently, and the next
                // write attempt only re-dirtied if another mutation
                // happened in between. A user who made one edit and
                // then closed Burp lost the edit without any signal.
                dirty.set(true);
                com.flechazo.apisentinel.logging.LeveledLogger staticLogger =
                        new com.flechazo.apisentinel.logging.LeveledLogger(null);
                staticLogger.warn("[PersistentApiRepository] 持久化失败，已重标 dirty 等待下次重试");
            }
        }
    }

    @Override
    public void add(ApiEntry entry) {
        delegate.add(entry);
        markDirty();
    }

    @Override
    public void addAll(Collection<ApiEntry> entries) {
        delegate.addAll(entries);
        markDirty();
    }

    @Override
    public boolean remove(String apiPath) {
        boolean result = delegate.remove(apiPath);
        if (result) markDirty();
        return result;
    }

    @Override
    public void removeByIndices(List<Integer> indices) {
        delegate.removeByIndices(indices);
        markDirty();
    }

    @Override
    public Optional<ApiEntry> findByPath(String apiPath) {
        return delegate.findByPath(apiPath);
    }

    @Override
    public Optional<ApiEntry> findByMethodAndPath(String httpMethod, String apiPath) {
        return delegate.findByMethodAndPath(httpMethod, apiPath);
    }

    @Override
    public ApiEntry getByIndex(int index) {
        return delegate.getByIndex(index);
    }

    @Override
    public List<ApiEntry> findAll() {
        return delegate.findAll();
    }

    @Override
    public List<ApiEntry> findByStatus(ApiStatus status) {
        return delegate.findByStatus(status);
    }

    @Override
    public java.util.Set<String> getKnownDomains() {
        return delegate.getKnownDomains();
    }

    @Override
    public List<ApiEntry> findByDomain(String domain) {
        return delegate.findByDomain(domain);
    }

    @Override
    public int size() {
        return delegate.size();
    }

    @Override
    public void clear() {
        delegate.clear();
        markDirty();
    }

    @Override
    public void updateStatus(String apiPath, ApiStatus status, VulnType vulnType, String result) {
        delegate.updateStatus(apiPath, status, vulnType, result);
        markDirty();
    }

    @Override
    public void updateDomain(String apiPath, String domain) {
        delegate.updateDomain(apiPath, domain);
        markDirty();
    }

    @Override
    public void updateDomain(ApiEntry entry, String domain) {
        delegate.updateDomain(entry, domain);
        markDirty();
    }

    @Override
    public ApiEntry updatePath(String oldPath, String newPath) {
        ApiEntry updated = delegate.updatePath(oldPath, newPath);
        if (updated != null) markDirty();
        return updated;
    }

    @Override
    public void updateMethod(String apiPath, String method) {
        delegate.updateMethod(apiPath, method);
        markDirty();
    }

    @Override
    public void updateNote(String apiPath, String note) {
        delegate.updateNote(apiPath, note);
        markDirty();
    }

    @Override
    public boolean contains(String httpMethod, String apiPath) {
        return delegate.contains(httpMethod, apiPath);
    }

    @Override
    public void moveTestedToTop() {
        delegate.moveTestedToTop();
        markDirty();
    }

    @Override
    public void save() {
        trySave();
    }

    @Override
    public boolean trySave() {
        return saveInternal();
    }

    /** Internal form of {@link #save()} that returns whether the write
     *  actually succeeded. {@code flushIfDirty} consults this so it can
     *  re-set the dirty flag on failure (P0-12). The public save() keeps
     *  its void signature so the {@link ApiRepository} interface contract
     *  is preserved. */
    private boolean saveInternal() {
        try {
            Path parent = dataFilePath.getParent();
            if (parent != null) {
                Files.createDirectories(parent);
                // P1-5: keep the directory 700 so a non-privileged local
                // user can't list the secrets we're about to write.
                AppPaths.tightenDirectoryPermissions(parent);
            }
            List<ApiEntry> all = delegate.findAll();
            String json = JsonUtils.toJson(all);
            Path tmpFile = dataFilePath.resolveSibling(dataFilePath.getFileName() + ".tmp");
            // Write + fsync the temp file before the atomic rename so a crash
            // between write and rename cannot leave a zero-byte durable file
            // (filesystem metadata committed but data not flushed).
            try (java.nio.channels.FileChannel ch = java.nio.channels.FileChannel.open(
                    tmpFile,
                    java.nio.file.StandardOpenOption.CREATE,
                    java.nio.file.StandardOpenOption.WRITE,
                    java.nio.file.StandardOpenOption.TRUNCATE_EXISTING)) {
                ch.write(java.nio.ByteBuffer.wrap(json.getBytes(java.nio.charset.StandardCharsets.UTF_8)));
                ch.force(true);
            }
            // P1-5: set 600 on the tmp file BEFORE the atomic rename, so
            // the destination inherits owner-only perms the instant it
            // becomes live. data.json can carry captured cookies, auth
            // headers, and session IDs from every endpoint the user has
            // browsed through Burp — group/other read here is a direct
            // credential leak to any local user on the box.
            try {
                java.nio.file.attribute.PosixFileAttributeView view =
                        Files.getFileAttributeView(tmpFile, java.nio.file.attribute.PosixFileAttributeView.class);
                if (view != null) {
                    view.setPermissions(java.nio.file.attribute.PosixFilePermissions.fromString("rw-------"));
                }
            } catch (UnsupportedOperationException ignored) {
                // Non-POSIX FS (Windows) — ACLs take over.
            }
            Files.move(tmpFile, dataFilePath, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
            // fsync the parent directory so the rename is durable on Linux
            fsyncDir(parent);
            logger.info("已保存 %d 条 API 数据到 %s", all.size(), dataFilePath);
            return true;
        } catch (IOException e) {
            logger.error("保存数据失败", e);
            return false;
        }
    }

    private static void fsyncDir(Path dir) {
        if (dir == null) return;
        try (java.nio.channels.FileChannel ch = java.nio.channels.FileChannel.open(dir)) {
            ch.force(true);
        } catch (Exception ignored) {
            // Not all platforms support opening a directory for fsync
        }
    }

    @Override
    public void load() {
        try {
            if (!Files.exists(dataFilePath)) {
                Path legacyPath = dataFilePath.getParent().getParent()
                        .resolve(".api-highlighter").resolve("data.json");
                if (Files.exists(legacyPath)) {
                    logger.info("发现旧数据文件 %s，正在迁移到 %s", legacyPath, dataFilePath);
                    Path parent = dataFilePath.getParent();
                    if (parent != null) Files.createDirectories(parent);
                    Files.copy(legacyPath, dataFilePath);
                    logger.info("数据迁移完成（旧文件已保留作为备份）");
                }
            }

            if (!Files.exists(dataFilePath)) {
                logger.info("数据文件不存在，跳过加载: %s", dataFilePath);
                return;
            }
            String json = Files.readString(dataFilePath);
            List<ApiEntry> entries = JsonUtils.fromJson(json);
            delegate.addAll(entries);
            logger.debug("已加载 %d 条 API 数据", entries.size());
        } catch (Exception e) {
            logger.error("加载数据失败", e);
            try {
                Path backup = dataFilePath.resolveSibling(dataFilePath.getFileName() + ".corrupted");
                if (Files.exists(dataFilePath)) {
                    Files.copy(dataFilePath, backup, StandardCopyOption.REPLACE_EXISTING);
                    logger.warn("已备份损坏文件到: %s", backup);
                }
            } catch (IOException ex) {
                logger.warn("备份文件失败: %s", ex.getMessage());
            }
        }
    }

    @Override
    public void addChangeListener(Runnable listener) {
        delegate.addChangeListener(listener);
    }

    @Override
    public void clearChangeListeners() {
        delegate.clearChangeListeners();
    }

    public void shutdown() {
        flushIfDirty();
        scheduler.shutdownNow();
        try {
            scheduler.awaitTermination(3, TimeUnit.SECONDS);
        } catch (InterruptedException ignored) {
            Thread.currentThread().interrupt();
        }
    }
}
