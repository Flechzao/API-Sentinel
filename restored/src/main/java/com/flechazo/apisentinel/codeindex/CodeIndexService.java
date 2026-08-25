package com.flechazo.apisentinel.codeindex;

import com.flechazo.apisentinel.codeindex.parser.*;
import com.flechazo.apisentinel.config.CodeRepo;
import com.flechazo.apisentinel.logging.LeveledLogger;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.reflect.TypeToken;

import java.io.IOException;
import java.lang.reflect.Type;
import java.nio.file.*;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

/**
 * 代码索引服务——索引 Java/Python/Node 代码仓库，提供路由匹配、grep 正则搜索、
 * 危险 sink 自动标注（SinkMap）、污点回溯。索引结果缓存到 code-index.json。
 */
public class CodeIndexService {

    public record IndexedRoute(RouteEntry route, String repoName) {}

    private final List<RouteParser> parsers;
    private final Map<String, List<IndexedRoute>> index = new ConcurrentHashMap<>();
    private final LeveledLogger logger;
    private final Gson gson = new GsonBuilder().setPrettyPrinting().create();
    private volatile SinkMap sinkMap;
    /** AtomicBoolean + compareAndSet closes the check-then-act race the old
     *  {@code volatile boolean} had (two concurrent triggers could both pass
     *  the {@code if (indexing)} check and double-index). */
    private final java.util.concurrent.atomic.AtomicBoolean indexing =
            new java.util.concurrent.atomic.AtomicBoolean(false);

    private static final Path INDEX_FILE = com.flechazo.apisentinel.config.AppPaths.codeIndexFile();

    private static final Set<String> DEFAULT_EXCLUDES = Set.of(
            "node_modules", ".git", "build", "target", "dist", "__pycache__", ".venv");

    public CodeIndexService(LeveledLogger logger) {
        this.logger = logger;
        this.parsers = List.of(
                new JavaRouteParser(),
                new PythonRouteParser(),
                new NodeRouteParser()
        );
    }

    public int indexRepo(CodeRepo repo) {
        return indexRepo(repo, true);
    }

    public int indexRepo(CodeRepo repo, boolean buildSinkMap) {
        if (!indexing.compareAndSet(false, true)) {
            logger.warn("索引正在进行中，跳过");
            return 0;
        }
        try {
            removeRepoIndex(repo.getName());
            int count = doIndex(Path.of(repo.getPath()), repo.getName());
            repo.setIndexed(true);
            repo.setRouteCount(count);
            if (buildSinkMap) {
                this.sinkMap = SinkMap.scan(List.of(repo), logger);
            }
            return count;
        } finally {
            indexing.set(false);
        }
    }

    public void indexAll(List<CodeRepo> repos) {
        if (!indexing.compareAndSet(false, true)) {
            logger.warn("索引正在进行中，跳过");
            return;
        }
        try {
            index.clear();
            for (CodeRepo repo : repos) {
                int count = doIndex(Path.of(repo.getPath()), repo.getName());
                repo.setIndexed(true);
                repo.setRouteCount(count);
            }
            this.sinkMap = SinkMap.scan(repos, logger);
            if (this.sinkMap != null) {
                this.sinkMap.save(gson);
            }
            saveIndex(repos);
        } finally {
            indexing.set(false);
        }
    }

    public void removeRepoIndex(String repoName) {
        index.values().forEach(list -> list.removeIf(ir -> ir.repoName().equals(repoName)));
        index.entrySet().removeIf(e -> e.getValue().isEmpty());
    }

    @Deprecated
    public void indexRepository(Path repoPath, List<String> excludePatterns) {
        if (!indexing.compareAndSet(false, true)) {
            logger.warn("索引正在进行中，跳过");
            return;
        }
        try {
            index.clear();
            doIndex(repoPath, repoPath.getFileName() != null ? repoPath.getFileName().toString() : "default");
        } finally {
            indexing.set(false);
        }
    }

    private int doIndex(Path repoPath, String repoName) {
        logger.info("开始索引代码仓库: %s (%s)", repoName, repoPath);
        long start = System.currentTimeMillis();
        int[] count = {0};

        try {
            Files.walkFileTree(repoPath, new SimpleFileVisitor<>() {
                @Override
                public FileVisitResult preVisitDirectory(Path dir, BasicFileAttributes attrs) {
                    String dirName = dir.getFileName().toString();
                    if (DEFAULT_EXCLUDES.contains(dirName)) return FileVisitResult.SKIP_SUBTREE;
                    return FileVisitResult.CONTINUE;
                }

                @Override
                public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) {
                    if (attrs.size() > 500_000) return FileVisitResult.CONTINUE;
                    for (RouteParser parser : parsers) {
                        if (parser.canParse(file)) {
                            try {
                                String content = Files.readString(file);
                                List<RouteEntry> entries = parser.parseFile(file, content);
                                for (RouteEntry entry : entries) {
                                    index.computeIfAbsent(entry.normalizedPattern(), k -> new ArrayList<>())
                                            .add(new IndexedRoute(entry, repoName));
                                    count[0]++;
                                }
                            } catch (IOException e) {
                                logger.debug("读取文件失败: %s", file);
                            }
                            break;
                        }
                    }
                    return FileVisitResult.CONTINUE;
                }
            });
        } catch (IOException e) {
            logger.error("索引代码仓库失败: %s", e.getMessage());
        }

        long elapsed = System.currentTimeMillis() - start;
        logger.info("索引完成 [%s]: %d 条路由, 耗时 %dms", repoName, count[0], elapsed);
        return count[0];
    }

    private static final Set<String> COMMON_SEGMENTS = Set.of(
            "api", "v1", "v2", "v3", "v4", ":param", "");

    public List<RouteEntry> findByPath(String apiPath) {
        String normalized = RouteEntry.normalize(apiPath);
        List<IndexedRoute> exact = index.get(normalized);
        if (exact != null && !exact.isEmpty()) {
            return exact.stream().map(IndexedRoute::route).collect(Collectors.toList());
        }

        String[] searchSegments = normalized.split("/");
        Set<String> meaningfulSearch = java.util.Arrays.stream(searchSegments)
                .filter(s -> !s.isEmpty() && !COMMON_SEGMENTS.contains(s))
                .collect(Collectors.toSet());

        if (meaningfulSearch.isEmpty()) return List.of();

        List<RouteEntry> fuzzy = index.entrySet().stream()
                .filter(e -> {
                    String key = e.getKey();
                    if (key.length() <= 1) return false;
                    String[] keySegments = key.split("/");
                    long shared = meaningfulSearch.stream()
                            .filter(s -> java.util.Arrays.asList(keySegments).contains(s))
                            .count();
                    return shared >= 2 || key.contains(normalized) || normalized.contains(key) && key.length() > 5;
                })
                .flatMap(e -> e.getValue().stream())
                .map(IndexedRoute::route)
                .limit(10)
                .collect(Collectors.toList());

        if (!fuzzy.isEmpty()) return fuzzy;

        String lastSegment = lastMeaningfulSegment(searchSegments);
        if (lastSegment == null) return List.of();
        return findByLastSegment(lastSegment, null);
    }

    public List<RouteEntry> findByPathAndDomain(String apiPath, String domain, List<CodeRepo> repos) {
        if (domain == null || domain.isEmpty()) return findByPath(apiPath);

        Set<String> matchingRepoNames = repos.stream()
                .filter(r -> r.matchesDomain(domain))
                .map(CodeRepo::getName)
                .collect(Collectors.toSet());

        if (matchingRepoNames.isEmpty()) return findByPath(apiPath);

        String normalized = RouteEntry.normalize(apiPath);

        List<IndexedRoute> exact = index.get(normalized);
        if (exact != null && !exact.isEmpty()) {
            List<RouteEntry> filtered = exact.stream()
                    .filter(ir -> matchingRepoNames.contains(ir.repoName()))
                    .map(IndexedRoute::route)
                    .collect(Collectors.toList());
            if (!filtered.isEmpty()) return filtered;
        }

        String[] searchSegments = normalized.split("/");
        Set<String> meaningfulSearch = java.util.Arrays.stream(searchSegments)
                .filter(s -> !s.isEmpty() && !COMMON_SEGMENTS.contains(s))
                .collect(Collectors.toSet());

        if (meaningfulSearch.isEmpty()) return List.of();

        List<RouteEntry> fuzzy = index.entrySet().stream()
                .filter(e -> {
                    String key = e.getKey();
                    if (key.length() <= 1) return false;
                    String[] keySegments = key.split("/");
                    long shared = meaningfulSearch.stream()
                            .filter(s -> java.util.Arrays.asList(keySegments).contains(s))
                            .count();
                    return shared >= 2 || key.contains(normalized) || normalized.contains(key) && key.length() > 5;
                })
                .flatMap(e -> e.getValue().stream())
                .filter(ir -> matchingRepoNames.contains(ir.repoName()))
                .map(IndexedRoute::route)
                .limit(10)
                .collect(Collectors.toList());

        if (!fuzzy.isEmpty()) return fuzzy;

        String lastSegment = lastMeaningfulSegment(searchSegments);
        if (lastSegment == null) return List.of();
        return findByLastSegment(lastSegment, matchingRepoNames);
    }

    private String lastMeaningfulSegment(String[] segments) {
        for (int i = segments.length - 1; i >= 0; i--) {
            String s = segments[i];
            if (!s.isEmpty() && !COMMON_SEGMENTS.contains(s) && !s.startsWith(":")) return s;
        }
        return null;
    }

    private List<RouteEntry> findByLastSegment(String segment, Set<String> repoFilter) {
        String lower = segment.toLowerCase();
        return index.entrySet().stream()
                .filter(e -> {
                    String key = e.getKey();
                    return key.toLowerCase().contains(lower);
                })
                .flatMap(e -> e.getValue().stream())
                .filter(ir -> repoFilter == null || repoFilter.contains(ir.repoName()))
                .map(IndexedRoute::route)
                .limit(10)
                .collect(Collectors.toList());
    }

    public Map<String, List<RouteEntry>> getAllRoutes() {
        Map<String, List<RouteEntry>> result = new HashMap<>();
        for (var entry : index.entrySet()) {
            result.put(entry.getKey(),
                    entry.getValue().stream().map(IndexedRoute::route).collect(Collectors.toList()));
        }
        return result;
    }

    public int getRouteCount() {
        return index.values().stream().mapToInt(List::size).sum();
    }

    public Set<String> getIndexedPaths() {
        return index.keySet();
    }

    public boolean isIndexing() {
        return indexing.get();
    }

    public String getSourceCode(RouteEntry entry) {
        try {
            List<String> lines = Files.readAllLines(entry.sourceFile());
            int start = Math.max(0, entry.startLine() - 3);
            int end = Math.min(lines.size(), entry.startLine() + 30);
            StringBuilder sb = new StringBuilder();
            for (int i = start; i < end; i++) {
                sb.append(String.format("%4d | %s\n", i + 1, lines.get(i)));
            }
            return sb.toString();
        } catch (IOException e) {
            return "无法读取源码: " + e.getMessage();
        }
    }

    public String getFullMethodSource(RouteEntry entry) {
        try {
            List<String> lines = Files.readAllLines(entry.sourceFile());
            int start = Math.max(0, entry.startLine() - 3);
            int end = findMethodEnd(lines, entry.startLine() - 1);
            end = Math.min(end, start + 200);
            StringBuilder sb = new StringBuilder();
            for (int i = start; i < end; i++) {
                sb.append(String.format("%4d | %s\n", i + 1, lines.get(i)));
            }
            return sb.toString();
        } catch (IOException e) {
            return "无法读取源码: " + e.getMessage();
        }
    }

    private int findMethodEnd(List<String> lines, int startIdx) {
        int braceCount = 0;
        boolean foundOpen = false;
        for (int i = startIdx; i < lines.size(); i++) {
            String line = lines.get(i);
            for (char c : line.toCharArray()) {
                if (c == '{') { braceCount++; foundOpen = true; }
                else if (c == '}') { braceCount--; }
            }
            if (foundOpen && braceCount <= 0) {
                return i + 1;
            }
        }
        return Math.min(lines.size(), startIdx + 50);
    }

    public SinkMap getSinkMap() {
        return sinkMap;
    }

    public void setSinkMap(SinkMap sinkMap) {
        this.sinkMap = sinkMap;
    }

    // --- Persistence ---

    private record PersistedRoute(String repoName, String httpMethod, String routePattern,
                                  String normalizedPattern, String sourceFile,
                                  int startLine, int endLine, String methodName, String className) {}

    private record PersistedIndex(int version, Map<String, String> repoSignatures,
                                  Map<String, List<PersistedRoute>> routes) {}

    public void saveIndex(List<CodeRepo> repos) {
        try {
            Map<String, String> sigs = new LinkedHashMap<>();
            if (repos != null) {
                for (CodeRepo r : repos) sigs.put(r.getName(), r.getPath());
            }
            Map<String, List<PersistedRoute>> routeMap = new LinkedHashMap<>();
            for (var entry : index.entrySet()) {
                List<PersistedRoute> list = entry.getValue().stream()
                        .map(ir -> new PersistedRoute(
                                ir.repoName(), ir.route().httpMethod(), ir.route().routePattern(),
                                ir.route().normalizedPattern(), ir.route().sourceFile().toString(),
                                ir.route().startLine(), ir.route().endLine(),
                                ir.route().methodName(), ir.route().className()))
                        .collect(Collectors.toList());
                routeMap.put(entry.getKey(), list);
            }
            PersistedIndex pi = new PersistedIndex(1, sigs, routeMap);
            Files.createDirectories(INDEX_FILE.getParent());
            Files.writeString(INDEX_FILE, gson.toJson(pi));
            logger.info("代码索引已持久化: %d 条路由", getRouteCount());
        } catch (Exception e) {
            logger.error("保存代码索引失败: %s", e.getMessage());
        }
    }

    public boolean loadIndex(List<CodeRepo> repos) {
        if (!Files.exists(INDEX_FILE)) return false;
        try {
            String json = Files.readString(INDEX_FILE);
            Type type = new TypeToken<PersistedIndex>() {}.getType();
            PersistedIndex pi = gson.fromJson(json, type);
            if (pi == null || pi.version() != 1 || pi.routes() == null) return false;

            Map<String, String> currentSigs = new LinkedHashMap<>();
            if (repos != null) {
                for (CodeRepo r : repos) currentSigs.put(r.getName(), r.getPath());
            }
            if (!currentSigs.equals(pi.repoSignatures())) {
                logger.info("代码仓库配置已变更，需要重新索引");
                return false;
            }

            index.clear();
            int count = 0;
            for (var entry : pi.routes().entrySet()) {
                List<IndexedRoute> list = new ArrayList<>();
                for (PersistedRoute pr : entry.getValue()) {
                    RouteEntry re = new RouteEntry(
                            pr.httpMethod(), pr.routePattern(), pr.normalizedPattern(),
                            Path.of(pr.sourceFile()), pr.startLine(), pr.endLine(),
                            pr.methodName(), pr.className());
                    list.add(new IndexedRoute(re, pr.repoName()));
                    count++;
                }
                index.put(entry.getKey(), list);
            }

            if (repos != null) {
                for (CodeRepo repo : repos) {
                    long repoCount = index.values().stream()
                            .flatMap(List::stream)
                            .filter(ir -> ir.repoName().equals(repo.getName()))
                            .count();
                    repo.setIndexed(true);
                    repo.setRouteCount((int) repoCount);
                }
            }

            logger.info("从缓存加载代码索引: %d 条路由", count);

            SinkMap loaded = SinkMap.load(gson);
            if (loaded != null) {
                this.sinkMap = loaded;
                logger.info("从缓存加载 SinkMap: %d 个 sink", loaded.totalSinkCount());
            }

            return true;
        } catch (Exception e) {
            logger.error("加载代码索引缓存失败: %s", e.getMessage());
            return false;
        }
    }
}
