package com.flechazo.apisentinel.matching;

import com.flechazo.apisentinel.model.ApiEntry;
import com.flechazo.apisentinel.util.PatternUtils;

import java.util.*;
import java.util.concurrent.locks.ReentrantReadWriteLock;

public class FuzzyMatchEngine implements MatchEngine {

    private AhoCorasick automaton;
    private final List<ApiEntry> entries = new ArrayList<>();
    private final ReentrantReadWriteLock lock = new ReentrantReadWriteLock();

    public FuzzyMatchEngine() {
        this.automaton = new AhoCorasick(List.of());
    }

    @Override
    public List<ApiEntry> match(String urlPath, String requestBody) {
        lock.readLock().lock();
        try {
            String searchText = (urlPath + (requestBody != null ? " " + requestBody : "")).toLowerCase();
            List<ApiEntry> found = automaton.search(searchText);
            // Prefer the MOST SPECIFIC (longest) matching pattern first.
            // RPC-gateway APIs share one URL path and differ by a query/body
            // param (e.g. InnerAction=GetDataservicePeeringReferencedProjects),
            // so several registered action names are substrings of the same
            // request. Without this sort, a shorter name (getDataServicePeering)
            // would shadow a longer one (getDataservicePeeringReferencedProjects)
            // and steal its traffic — the Aho-Corasick returns matches in
            // text-discovery order, where the shorter prefix appears first.
            found.sort((a, b) -> Integer.compare(
                    PatternUtils.normalizePathForMatching(b.getApiPath()).length(),
                    PatternUtils.normalizePathForMatching(a.getApiPath()).length()));
            return found;
        } finally {
            lock.readLock().unlock();
        }
    }

    @Override
    public void rebuild(Collection<ApiEntry> newEntries) {
        lock.writeLock().lock();
        try {
            entries.clear();
            entries.addAll(newEntries);
            this.automaton = new AhoCorasick(entries);
        } finally {
            lock.writeLock().unlock();
        }
    }

    @Override
    public void addEntry(ApiEntry entry) {
        lock.writeLock().lock();
        try {
            entries.add(entry);
            this.automaton = new AhoCorasick(entries);
        } finally {
            lock.writeLock().unlock();
        }
    }

    public void addAll(Collection<ApiEntry> newEntries) {
        if (newEntries == null || newEntries.isEmpty()) return;
        lock.writeLock().lock();
        try {
            entries.addAll(newEntries);
            this.automaton = new AhoCorasick(entries);
        } finally {
            lock.writeLock().unlock();
        }
    }

    @Override
    public void removeEntry(String apiPath) {
        lock.writeLock().lock();
        try {
            entries.removeIf(e -> e.getApiPath().equalsIgnoreCase(apiPath));
            this.automaton = new AhoCorasick(entries);
        } finally {
            lock.writeLock().unlock();
        }
    }

    static class AhoCorasick {
        private final Map<Integer, int[]> goTo;
        private final int[] fail;
        private final List<List<ApiEntry>> output;
        private final int stateCount;

        AhoCorasick(Collection<ApiEntry> entries) {
            List<ApiEntry> allEntries = new ArrayList<>(entries);
            if (allEntries.isEmpty()) {
                goTo = new HashMap<>();
                goTo.put(0, emptyRow());
                fail = new int[]{0};
                output = new ArrayList<>();
                output.add(new ArrayList<>());
                stateCount = 1;
                return;
            }

            int maxStates = allEntries.stream()
                    .mapToInt(e -> PatternUtils.normalizePathForMatching(e.getApiPath()).length())
                    .sum() + 1;
            maxStates = Math.max(maxStates, 2);

            goTo = new HashMap<>(maxStates);
            goTo.put(0, emptyRow());
            fail = new int[maxStates];
            output = new ArrayList<>(maxStates);
            for (int i = 0; i < maxStates; i++) {
                output.add(new ArrayList<>());
            }

            int states = 1;

            for (ApiEntry entry : allEntries) {
                String pattern = PatternUtils.normalizePathForMatching(entry.getApiPath());
                if (pattern.isEmpty()) continue;
                int cur = 0;
                for (int i = 0; i < pattern.length(); i++) {
                    int ch = pattern.charAt(i) & 0xFF;
                    int[] row = goTo.computeIfAbsent(cur, k -> emptyRow());
                    if (row[ch] == -1) {
                        row[ch] = states;
                        goTo.put(states, emptyRow());
                        states++;
                    }
                    cur = row[ch];
                }
                output.get(cur).add(entry);
            }

            this.stateCount = states;

            // BFS to build fail links
            Queue<Integer> queue = new LinkedList<>();
            int[] root = goTo.get(0);
            for (int c = 0; c < 256; c++) {
                if (root[c] != -1) {
                    fail[goTo.get(0)[c]] = 0;
                    queue.add(root[c]);
                } else {
                    root[c] = 0;
                }
            }

            while (!queue.isEmpty()) {
                int u = queue.poll();
                int[] uRow = goTo.get(u);
                if (uRow == null) continue;
                for (int c = 0; c < 256; c++) {
                    int v = uRow[c];
                    if (v != -1) {
                        fail[v] = goTo.get(fail[u])[c];
                        output.get(v).addAll(output.get(fail[v]));
                        queue.add(v);
                    } else {
                        uRow[c] = goTo.get(fail[u])[c];
                    }
                }
            }
        }

        private static int[] emptyRow() {
            int[] row = new int[256];
            Arrays.fill(row, -1);
            return row;
        }

        List<ApiEntry> search(String text) {
            Set<ApiEntry> found = new LinkedHashSet<>();
            int state = 0;
            for (int i = 0; i < text.length(); i++) {
                int c = text.charAt(i);
                // Patterns (normalized API paths) are ASCII/Latin-1. A char above
                // U+00FF (e.g. CJK) cannot be part of any pattern. Previously
                // `c & 0xFF` truncated it to its low byte (e.g. '中' -> 0x2D '-'),
                // which could spuriously advance the automaton and cause false
                // matches. Reset state instead — this char breaks any partial match.
                int ch;
                if (c > 0xFF) {
                    state = 0;
                    continue;
                }
                ch = c;
                int[] row = goTo.get(state);
                if (row == null) {
                    state = 0;
                    continue;
                }
                state = row[ch];
                if (state >= 0 && state < output.size() && !output.get(state).isEmpty()) {
                    found.addAll(output.get(state));
                }
            }
            return new ArrayList<>(found);
        }
    }
}
