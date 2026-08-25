package com.flechazo.apisentinel.matching;

import com.flechazo.apisentinel.model.ApiEntry;
import com.flechazo.apisentinel.util.PatternUtils;

import java.util.*;
import java.util.concurrent.locks.ReentrantReadWriteLock;

/**
 * Trie-based match engine supporting:
 * <ul>
 *   <li>Exact path matching with wildcard segments ({id}, :id, numeric, UUID, etc.)</li>
 *   <li>Glob-star matching: a trailing "**" matches any remaining sub-path</li>
 * </ul>
 *
 * Examples:
 * <pre>
 *   /api/v1/users/{id}     matches  /api/v1/users/42
 *   /api/v1/admin/**        matches  /api/v1/admin/users/123/profile
 * </pre>
 */
public class TrieMatchEngine implements MatchEngine {

    private volatile TrieNode root = new TrieNode();
    private final ReentrantReadWriteLock lock = new ReentrantReadWriteLock();

    private static class TrieNode {
        final Map<String, TrieNode> children = new HashMap<>();
        TrieNode wildcardChild;       // matches any single segment ({id}, numeric, etc.)
        ApiEntry terminalEntry;       // non-null if a pattern ends here
        ApiEntry globStarEntry;       // non-null if "**" is registered here (matches all sub-paths)
    }

    @Override
    public List<ApiEntry> match(String urlPath, String requestBody) {
        lock.readLock().lock();
        try {
            return matchExact(urlPath);
        } finally {
            lock.readLock().unlock();
        }
    }

    /**
     * Match a URL path against all registered patterns.
     * Returns the best match: exact terminal > glob-star (deepest wins).
     */
    public List<ApiEntry> matchExact(String urlPath) {
        lock.readLock().lock();
        try {
            String normalized = PatternUtils.normalizePathForMatching(urlPath);
            String[] segments = PatternUtils.splitPathSegments(normalized);
            TrieNode node = root;

            // Track the deepest glob-star entry seen along the walk
            ApiEntry deepestGlob = root.globStarEntry;

            for (String seg : segments) {
                // Try exact child first, then wildcard child
                TrieNode child = node.children.get(seg);
                if (child == null) {
                    child = node.wildcardChild;
                }
                if (child == null) {
                    // No further match — return glob-star if we saw one
                    if (deepestGlob != null) return List.of(deepestGlob);
                    return List.of();
                }
                node = child;

                // Update deepest glob-star seen so far
                if (node.globStarEntry != null) {
                    deepestGlob = node.globStarEntry;
                }
            }

            // Exact terminal match takes priority
            if (node.terminalEntry != null) {
                return List.of(node.terminalEntry);
            }
            // Fall back to deepest glob-star
            if (deepestGlob != null) {
                return List.of(deepestGlob);
            }
            return List.of();
        } finally {
            lock.readLock().unlock();
        }
    }

    @Override
    public void rebuild(Collection<ApiEntry> entries) {
        lock.writeLock().lock();
        try {
            root = new TrieNode();
            for (ApiEntry entry : entries) {
                insertEntry(entry);
            }
        } finally {
            lock.writeLock().unlock();
        }
    }

    @Override
    public void addEntry(ApiEntry entry) {
        lock.writeLock().lock();
        try {
            insertEntry(entry);
        } finally {
            lock.writeLock().unlock();
        }
    }

    @Override
    public void removeEntry(String apiPath) {
        lock.writeLock().lock();
        try {
            String normalized = PatternUtils.normalizePathForMatching(apiPath);
            String[] segments = PatternUtils.splitPathSegments(normalized);
            removeFromTrie(root, segments, 0);
        } finally {
            lock.writeLock().unlock();
        }
    }

    private void insertEntry(ApiEntry entry) {
        String normalized = PatternUtils.normalizePathForMatching(entry.getApiPath());
        String[] segments = PatternUtils.splitPathSegments(normalized);
        TrieNode node = root;

        for (int i = 0; i < segments.length; i++) {
            String seg = segments[i];

            // If this segment is "**", register as glob-star on the CURRENT node and stop
            if (PatternUtils.isGlobStar(seg)) {
                node.globStarEntry = entry;
                return;
            }

            if (PatternUtils.isWildcardSegment(seg)) {
                if (node.wildcardChild == null) {
                    node.wildcardChild = new TrieNode();
                }
                node = node.wildcardChild;
            } else {
                node = node.children.computeIfAbsent(seg, k -> new TrieNode());
            }
        }
        node.terminalEntry = entry;
    }

    private boolean removeFromTrie(TrieNode node, String[] segments, int depth) {
        if (depth == segments.length) {
            if (node.terminalEntry != null) {
                node.terminalEntry = null;
                return node.children.isEmpty() && node.wildcardChild == null && node.globStarEntry == null;
            }
            return false;
        }

        String seg = segments[depth];

        // Handle "**" removal
        if (PatternUtils.isGlobStar(seg)) {
            if (node.globStarEntry != null) {
                node.globStarEntry = null;
                return node.terminalEntry == null && node.children.isEmpty() && node.wildcardChild == null;
            }
            return false;
        }

        if (PatternUtils.isWildcardSegment(seg)) {
            if (node.wildcardChild != null && removeFromTrie(node.wildcardChild, segments, depth + 1)) {
                node.wildcardChild = null;
                return node.terminalEntry == null && node.children.isEmpty() && node.globStarEntry == null;
            }
        } else {
            TrieNode child = node.children.get(seg);
            if (child != null && removeFromTrie(child, segments, depth + 1)) {
                node.children.remove(seg);
                return node.terminalEntry == null && node.children.isEmpty()
                        && node.wildcardChild == null && node.globStarEntry == null;
            }
        }
        return false;
    }
}
