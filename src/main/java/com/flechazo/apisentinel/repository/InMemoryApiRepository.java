package com.flechazo.apisentinel.repository;

import com.flechazo.apisentinel.model.ApiEntry;
import com.flechazo.apisentinel.model.ApiStatus;
import com.flechazo.apisentinel.model.VulnType;

import java.util.*;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.locks.ReentrantReadWriteLock;
import java.util.stream.Collectors;
public class InMemoryApiRepository implements ApiRepository {

    private final List<ApiEntry> entries = new ArrayList<>();
    private final Map<String, ApiEntry> pathIndex = new HashMap<>();
    private final Map<String, Set<ApiEntry>> byDomain = new HashMap<>();
    private final ReentrantReadWriteLock lock = new ReentrantReadWriteLock();
    private final List<Runnable> changeListeners = new CopyOnWriteArrayList<>();

    private static String normDomain(String d) {
        return d != null ? d.trim().toLowerCase() : "";
    }

    private void indexAdd(ApiEntry entry) {
        byDomain.computeIfAbsent(normDomain(entry.getDomain()), k -> new HashSet<>()).add(entry);
    }

    private void indexRemove(ApiEntry entry, String oldDomain) {
        Set<ApiEntry> bucket = byDomain.get(normDomain(oldDomain));
        if (bucket != null) {
            bucket.remove(entry);
            if (bucket.isEmpty()) byDomain.remove(normDomain(oldDomain));
        }
    }

    @Override
    public void add(ApiEntry entry) {
        lock.writeLock().lock();
        try {
            String key = normalizeKey(entry.getHttpMethod(), entry.getApiPath());
            if (!pathIndex.containsKey(key)) {
                entries.add(entry);
                pathIndex.put(key, entry);
                indexAdd(entry);
            }
        } finally {
            lock.writeLock().unlock();
        }
        fireChange();
    }

    @Override
    public void addAll(Collection<ApiEntry> newEntries) {
        lock.writeLock().lock();
        try {
            for (ApiEntry entry : newEntries) {
                String key = normalizeKey(entry.getHttpMethod(), entry.getApiPath());
                if (!pathIndex.containsKey(key)) {
                    entries.add(entry);
                    pathIndex.put(key, entry);
                    indexAdd(entry);
                }
            }
        } finally {
            lock.writeLock().unlock();
        }
        fireChange();
    }

    @Override
    public boolean remove(String apiPath) {
        boolean removed = false;
        lock.writeLock().lock();
        try {
            String pathKey = normalizeKey(apiPath);
            List<String> keysToRemove = pathIndex.keySet().stream()
                    .filter(k -> k.endsWith(" " + pathKey))
                    .collect(Collectors.toList());
            for (String k : keysToRemove) {
                ApiEntry entry = pathIndex.remove(k);
                if (entry != null) {
                    indexRemove(entry, entry.getDomain());
                    entries.remove(entry);
                    removed = true;
                }
            }
        } finally {
            lock.writeLock().unlock();
        }
        if (removed) fireChange();
        return removed;
    }

    @Override
    public void removeByIndices(List<Integer> indices) {
        lock.writeLock().lock();
        try {
            List<Integer> sorted = indices.stream().sorted(Comparator.reverseOrder()).collect(Collectors.toList());
            for (int idx : sorted) {
                if (idx >= 0 && idx < entries.size()) {
                    ApiEntry removed = entries.remove(idx);
                    indexRemove(removed, removed.getDomain());
                    pathIndex.remove(normalizeKey(removed.getHttpMethod(), removed.getApiPath()));
                }
            }
        } finally {
            lock.writeLock().unlock();
        }
        fireChange();
    }

    @Override
    public Optional<ApiEntry> findByPath(String apiPath) {
        lock.readLock().lock();
        try {
            String pathKey = normalizeKey(apiPath);
            for (var e : pathIndex.entrySet()) {
                if (e.getKey().endsWith(" " + pathKey)) {
                    return Optional.of(e.getValue());
                }
            }
            return Optional.empty();
        } finally {
            lock.readLock().unlock();
        }
    }

    @Override
    public Optional<ApiEntry> findByMethodAndPath(String httpMethod, String apiPath) {
        lock.readLock().lock();
        try {
            return Optional.ofNullable(pathIndex.get(normalizeKey(httpMethod, apiPath)));
        } finally {
            lock.readLock().unlock();
        }
    }

    @Override
    public ApiEntry getByIndex(int index) {
        lock.readLock().lock();
        try {
            if (index >= 0 && index < entries.size()) {
                return entries.get(index);
            }
            return null;
        } finally {
            lock.readLock().unlock();
        }
    }

    @Override
    public List<ApiEntry> findAll() {
        lock.readLock().lock();
        try {
            return new ArrayList<>(entries);
        } finally {
            lock.readLock().unlock();
        }
    }

    @Override
    public List<ApiEntry> findByStatus(ApiStatus status) {
        lock.readLock().lock();
        try {
            return entries.stream()
                    .filter(e -> e.getStatus() == status)
                    .collect(Collectors.toList());
        } finally {
            lock.readLock().unlock();
        }
    }

    @Override
    public Set<String> getKnownDomains() {
        lock.readLock().lock();
        try {
            return new HashSet<>(byDomain.keySet());
        } finally {
            lock.readLock().unlock();
        }
    }

    @Override
    public List<ApiEntry> findByDomain(String domain) {
        lock.readLock().lock();
        try {
            Set<ApiEntry> bucket = byDomain.get(normDomain(domain));
            return bucket == null ? List.of() : new ArrayList<>(bucket);
        } finally {
            lock.readLock().unlock();
        }
    }

    @Override
    public int size() {
        lock.readLock().lock();
        try {
            return entries.size();
        } finally {
            lock.readLock().unlock();
        }
    }

    @Override
    public void clear() {
        lock.writeLock().lock();
        try {
            entries.clear();
            pathIndex.clear();
            byDomain.clear();
        } finally {
            lock.writeLock().unlock();
        }
        fireChange();
    }

    @Override
    public void updateStatus(String apiPath, ApiStatus status, VulnType vulnType, String result) {
        lock.writeLock().lock();
        try {
            ApiEntry entry = pathIndex.get(normalizeKey(apiPath));
            if (entry != null) {
                entry.updateStatus(status, vulnType, result);
            }
        } finally {
            lock.writeLock().unlock();
        }
        fireChange();
    }

    @Override
    public void updateDomain(String apiPath, String domain) {
        lock.writeLock().lock();
        try {
            ApiEntry entry = findEntryByPathUnsafe(apiPath);
            if (entry != null) {
                String old = entry.getDomain();
                entry.setDomain(domain);
                indexRemove(entry, old);
                indexAdd(entry);
            }
        } finally {
            lock.writeLock().unlock();
        }
    }

    @Override
    public void updateDomain(ApiEntry entry, String domain) {
        if (entry == null) return;
        lock.writeLock().lock();
        try {
            String old = entry.getDomain();
            entry.setDomain(domain);
            indexRemove(entry, old);
            indexAdd(entry);
        } finally {
            lock.writeLock().unlock();
        }
    }

    @Override
    public ApiEntry updatePath(String oldPath, String newPath) {
        lock.writeLock().lock();
        try {
            // Find entry by path (any method)
            ApiEntry oldEntry = null;
            String oldKey = null;
            String pathNorm = normalizeKey(oldPath);
            for (var e : pathIndex.entrySet()) {
                if (e.getKey().endsWith(" " + pathNorm)) {
                    oldKey = e.getKey();
                    oldEntry = e.getValue();
                    break;
                }
            }
            if (oldEntry == null) return null;
            pathIndex.remove(oldKey);
            String newKey = normalizeKey(oldEntry.getHttpMethod(), newPath);
            if (pathIndex.containsKey(newKey)) {
                pathIndex.put(oldKey, oldEntry);
                return null;
            }
            entries.remove(oldEntry);
            indexRemove(oldEntry, oldEntry.getDomain());
            ApiEntry newEntry = new ApiEntry(oldEntry, newPath);
            entries.add(newEntry);
            pathIndex.put(newKey, newEntry);
            indexAdd(newEntry);
            return newEntry;
        } finally {
            lock.writeLock().unlock();
        }
    }

    @Override
    public void updateMethod(String apiPath, String method) {
        lock.writeLock().lock();
        try {
            ApiEntry entry = findEntryByPathUnsafe(apiPath);
            if (entry != null) {
                String oldKey = normalizeKey(entry.getHttpMethod(), entry.getApiPath());
                pathIndex.remove(oldKey);
                entry.setHttpMethod(method);
                String newKey = normalizeKey(entry.getHttpMethod(), entry.getApiPath());
                pathIndex.put(newKey, entry);
            }
        } finally {
            lock.writeLock().unlock();
        }
    }

    @Override
    public void updateNote(String apiPath, String note) {
        lock.writeLock().lock();
        try {
            ApiEntry entry = findEntryByPathUnsafe(apiPath);
            if (entry != null) {
                entry.setNote(note);
            }
        } finally {
            lock.writeLock().unlock();
        }
    }

    @Override
    public boolean contains(String httpMethod, String apiPath) {
        lock.readLock().lock();
        try {
            return pathIndex.containsKey(normalizeKey(httpMethod, apiPath));
        } finally {
            lock.readLock().unlock();
        }
    }

    @Override
    public void moveTestedToTop() {
        lock.writeLock().lock();
        try {
            List<ApiEntry> tested = new ArrayList<>();
            List<ApiEntry> untested = new ArrayList<>();
            for (ApiEntry e : entries) {
                if (e.isTested()) {
                    tested.add(e);
                } else {
                    untested.add(e);
                }
            }
            entries.clear();
            entries.addAll(tested);
            entries.addAll(untested);
        } finally {
            lock.writeLock().unlock();
        }
        fireChange();
    }

    @Override
    public void save() {
        trySave();
    }

    @Override
    public boolean trySave() {
        // In-memory repo has no persistence — "save" is a no-op that
        // always succeeds. The return value stays honest: nothing to
        // write can't fail to write.
        return true;
    }

    @Override
    public void load() {}

    @Override
    public void addChangeListener(Runnable listener) {
        changeListeners.add(listener);
    }

    /** Disconnect all change listeners (UI components) so an unloaded extension's
     *  ClassLoader isn't pinned by Swing components still referenced here. */
    @Override
    public void clearChangeListeners() {
        changeListeners.clear();
    }

    protected List<ApiEntry> getEntriesRef() {
        return entries;
    }

    protected ReentrantReadWriteLock getLock() {
        return lock;
    }

    private String normalizeKey(String apiPath) {
        return apiPath != null ? apiPath.trim().toLowerCase() : "";
    }

    private String normalizeKey(String httpMethod, String apiPath) {
        String method = (httpMethod != null && !httpMethod.isEmpty()) ? httpMethod.trim().toUpperCase() : "*";
        String path = apiPath != null ? apiPath.trim().toLowerCase() : "";
        return method + " " + path;
    }

    /** Find entry by path only (ignoring method). Caller must hold lock. */
    private ApiEntry findEntryByPathUnsafe(String apiPath) {
        String pathKey = normalizeKey(apiPath);
        for (ApiEntry e : pathIndex.values()) {
            if (normalizeKey(e.getApiPath()).equals(pathKey)) {
                return e;
            }
        }
        return null;
    }

    private void fireChange() {
        // Listeners run on whatever thread triggered the change (often a
        // background worker). UI listeners must marshal themselves onto the
        // EDT; here we only guarantee one failing listener does not stop the
        // others.
        for (Runnable listener : changeListeners) {
            try {
                listener.run();
            } catch (Exception e) {
                System.err.println("[API-Sentinel] Repository change listener error: "
                        + e.getClass().getSimpleName() + ": " + e.getMessage());
            }
        }
    }
}
