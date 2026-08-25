package com.flechazo.apisentinel.repository;

import com.flechazo.apisentinel.model.ApiEntry;
import com.flechazo.apisentinel.model.ApiStatus;
import com.flechazo.apisentinel.model.VulnType;

import java.util.Collection;
import java.util.List;
import java.util.Optional;
import java.util.Set;

/**
 * API 仓库接口——接口清单的持久化抽象，支持内存和 JSON 文件两种实现。
 */
public interface ApiRepository {

    void add(ApiEntry entry);

    void addAll(Collection<ApiEntry> entries);

    boolean remove(String apiPath);

    void removeByIndices(List<Integer> indices);

    Optional<ApiEntry> findByPath(String apiPath);

    Optional<ApiEntry> findByMethodAndPath(String httpMethod, String apiPath);

    ApiEntry getByIndex(int index);

    List<ApiEntry> findAll();

    List<ApiEntry> findByStatus(ApiStatus status);

    /**
     * All distinct domains known to the repository (O(1) snapshot of a
     * maintained index). Used by focus-mode filtering on the traffic hot path
     * to avoid a full {@link #findAll()} scan per request.
     */
    Set<String> getKnownDomains();

    /**
     * Entries whose domain matches the given host (case-insensitive). Backed by
     * a maintained index so the per-request cost is O(matched) not O(all).
     */
    List<ApiEntry> findByDomain(String domain);

    int size();

    void clear();

    void updateStatus(String apiPath, ApiStatus status, VulnType vulnType, String result);

    void updateDomain(String apiPath, String domain);

    /**
     * Replace an entry's path (its identity key) with a new one, preserving
     * all other fields. Re-indexes path + domain indexes. Returns the new
     * entry, or null if oldPath not found / newPath already exists.
     */
    ApiEntry updatePath(String oldPath, String newPath);

    void updateMethod(String apiPath, String method);

    void updateNote(String apiPath, String note);

    boolean contains(String httpMethod, String apiPath);

    void moveTestedToTop();

    void save();

    /**
     * Mark the repository as having unsaved changes (analysis records added to
     * an entry mutate it outside the repository's own mutators, so the dirty
     * flag must be set explicitly to ensure the debounced flush + unload flush
     * persist them). No-op for non-persistent implementations.
     */
    default void markDirty() {}

    void load();

    void addChangeListener(Runnable listener);

    /** Disconnect all registered change listeners (e.g. on extension unload). */
    void clearChangeListeners();
}
