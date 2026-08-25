package com.flechazo.apisentinel.codeindex;

import com.flechazo.apisentinel.config.AppPaths;
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
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/** 危险 sink 映射表——定义 7 类 sink（SQL/CMD/文件/反序列化/SSRF/弱加密/不安全随机）的正则签名。 */
public class SinkMap {

    public enum SinkType { SQL, COMMAND, FILE_ACCESS, DESERIALIZATION, SSRF, CRYPTO, INSECURE_RANDOM }

    public record SinkEntry(SinkType type, String file, int line, String snippet, String className) {}

    private final Map<String, List<SinkEntry>> sinksByClass;
    private final List<SinkEntry> allSinks;

    private static final Set<String> DEFAULT_EXCLUDES = Set.of(
            "node_modules", ".git", "build", "target", "dist", "__pycache__", ".venv");

    private static final Map<SinkType, List<Pattern>> SINK_PATTERNS = buildSinkPatterns();

    private static final Pattern CLASS_DECL = Pattern.compile(
            "(?:public\\s+)?(?:abstract\\s+)?(?:class|interface|enum)\\s+(\\w+)");

    private SinkMap(Map<String, List<SinkEntry>> sinksByClass, List<SinkEntry> allSinks) {
        this.sinksByClass = sinksByClass;
        this.allSinks = allSinks;
    }

    public static SinkMap empty() {
        return new SinkMap(Map.of(), List.of());
    }

    public static SinkMap scan(List<CodeRepo> repos, LeveledLogger logger) {
        Map<String, List<SinkEntry>> byClass = new ConcurrentHashMap<>();
        List<SinkEntry> all = Collections.synchronizedList(new ArrayList<>());

        if (repos == null || repos.isEmpty()) return empty();

        for (CodeRepo repo : repos) {
            Path root;
            try {
                root = Path.of(repo.getPath());
            } catch (Exception e) {
                continue;
            }
            if (!Files.isDirectory(root)) continue;

            try {
                Files.walkFileTree(root, new SimpleFileVisitor<>() {
                    @Override
                    public FileVisitResult preVisitDirectory(Path dir, BasicFileAttributes attrs) {
                        String dirName = dir.getFileName() != null ? dir.getFileName().toString() : "";
                        if (DEFAULT_EXCLUDES.contains(dirName)) return FileVisitResult.SKIP_SUBTREE;
                        return FileVisitResult.CONTINUE;
                    }

                    @Override
                    public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) {
                        if (attrs.size() > 500_000) return FileVisitResult.CONTINUE;
                        String fileName = file.getFileName().toString().toLowerCase();
                        if (!isScannable(fileName)) return FileVisitResult.CONTINUE;

                        try {
                            List<String> lines = Files.readAllLines(file);
                            String currentClass = extractClassName(lines);
                            for (int i = 0; i < lines.size(); i++) {
                                String line = lines.get(i);
                                for (var entry : SINK_PATTERNS.entrySet()) {
                                    for (Pattern p : entry.getValue()) {
                                        if (p.matcher(line).find()) {
                                            SinkEntry sink = new SinkEntry(
                                                    entry.getKey(),
                                                    file.toString(),
                                                    i + 1,
                                                    line.trim(),
                                                    currentClass);
                                            all.add(sink);
                                            byClass.computeIfAbsent(currentClass, k -> new ArrayList<>()).add(sink);
                                            break;
                                        }
                                    }
                                }
                            }
                        } catch (IOException ignored) {}
                        return FileVisitResult.CONTINUE;
                    }
                });
            } catch (IOException e) {
                if (logger != null) logger.debug("[SinkMap] 扫描仓库失败: %s", e.getMessage());
            }
        }

        if (logger != null) {
            logger.info("[SinkMap] 扫描完成: %d 个 sink（SQL=%d, CMD=%d, FILE=%d, DESER=%d, SSRF=%d, CRYPTO=%d, RNG=%d）",
                    all.size(),
                    all.stream().filter(s -> s.type() == SinkType.SQL).count(),
                    all.stream().filter(s -> s.type() == SinkType.COMMAND).count(),
                    all.stream().filter(s -> s.type() == SinkType.FILE_ACCESS).count(),
                    all.stream().filter(s -> s.type() == SinkType.DESERIALIZATION).count(),
                    all.stream().filter(s -> s.type() == SinkType.SSRF).count(),
                    all.stream().filter(s -> s.type() == SinkType.CRYPTO).count(),
                    all.stream().filter(s -> s.type() == SinkType.INSECURE_RANDOM).count());
        }

        return new SinkMap(byClass, all);
    }

    public List<SinkEntry> sinksInClass(String className) {
        if (className == null) return List.of();
        List<SinkEntry> result = sinksByClass.get(className);
        return result != null ? List.copyOf(result) : List.of();
    }

    public boolean hasSinks(String className) {
        if (className == null) return false;
        List<SinkEntry> list = sinksByClass.get(className);
        return list != null && !list.isEmpty();
    }

    public List<SinkEntry> allSinksOfType(SinkType type) {
        return allSinks.stream().filter(s -> s.type() == type).toList();
    }

    /** Every sink across all indexed repos (for global codebase auditing). */
    public List<SinkEntry> allSinks() {
        return List.copyOf(allSinks);
    }

    public int totalSinkCount() {
        return allSinks.size();
    }

    public Set<String> classesWithSinks() {
        return Collections.unmodifiableSet(sinksByClass.keySet());
    }

    // --- Persistence ---

    public void save(Gson gson) {
        try {
            Path file = AppPaths.sinkMapFile();
            Files.createDirectories(file.getParent());
            Files.writeString(file, gson.toJson(allSinks));
        } catch (Exception ignored) {}
    }

    public static SinkMap load(Gson gson) {
        Path file = AppPaths.sinkMapFile();
        if (!Files.exists(file)) return null;
        try {
            String json = Files.readString(file);
            Type type = new TypeToken<List<SinkEntry>>() {}.getType();
            List<SinkEntry> loaded = gson.fromJson(json, type);
            if (loaded == null) return null;
            Map<String, List<SinkEntry>> byClass = new HashMap<>();
            for (SinkEntry entry : loaded) {
                byClass.computeIfAbsent(entry.className(), k -> new ArrayList<>()).add(entry);
            }
            return new SinkMap(byClass, loaded);
        } catch (Exception e) {
            return null;
        }
    }

    // --- Internal ---

    private static boolean isScannable(String fileName) {
        return fileName.endsWith(".java") || fileName.endsWith(".kt")
                || fileName.endsWith(".py") || fileName.endsWith(".js")
                || fileName.endsWith(".ts") || fileName.endsWith(".go");
    }

    private static String extractClassName(List<String> lines) {
        for (String line : lines) {
            Matcher m = CLASS_DECL.matcher(line);
            if (m.find()) return m.group(1);
        }
        return "Unknown";
    }

    private static Map<SinkType, List<Pattern>> buildSinkPatterns() {
        Map<SinkType, List<Pattern>> map = new EnumMap<>(SinkType.class);

        map.put(SinkType.SQL, List.of(
                Pattern.compile("\"\\s*(?:SELECT|INSERT|UPDATE|DELETE)\\s[^\"]*\"\\s*\\+"),
                Pattern.compile("jdbcTemplate\\s*\\.\\s*(?:query|update|execute)\\s*\\("),
                Pattern.compile("createNativeQuery\\s*\\("),
                Pattern.compile("createQuery\\s*\\([^)]*\\+"),
                Pattern.compile("\\.prepareStatement\\s*\\(\\s*[^\"\\s]"),
                Pattern.compile("String\\.format\\s*\\(\\s*\"(?:SELECT|INSERT|UPDATE|DELETE)")
        ));

        map.put(SinkType.COMMAND, List.of(
                Pattern.compile("Runtime\\s*\\.\\s*getRuntime\\s*\\(\\s*\\)\\s*\\.\\s*exec\\s*\\("),
                Pattern.compile("new\\s+ProcessBuilder\\s*\\("),
                Pattern.compile("os\\.system\\s*\\("),
                // subprocess.call/run/Popen/check_output AND the output-capturing
                // getstatusoutput/getoutput (shell=True under the hood — the sink
                // behind second-order shell-injection like unquoted -u{user} into
                // mysqldump). os.popen / commands.getoutput covered too.
                Pattern.compile("subprocess\\.(?:call|run|Popen|check_output|check_call|getstatusoutput|getoutput)\\s*\\("),
                Pattern.compile("os\\.popen\\s*\\(|commands\\.(?:popen|getoutput|getstatusoutput)\\s*\\("),
                Pattern.compile("exec\\s*\\(\\s*[^)]*\\+")
        ));

        map.put(SinkType.FILE_ACCESS, List.of(
                Pattern.compile("new\\s+File\\s*\\([^)]*\\+"),
                Pattern.compile("Paths?\\.(?:of|get)\\s*\\([^)]*\\+"),
                Pattern.compile("Files\\.(?:readAllLines|readString|readAllBytes|write|delete|copy|move)\\s*\\("),
                Pattern.compile("open\\s*\\([^)]*\\+")
        ));

        map.put(SinkType.DESERIALIZATION, List.of(
                Pattern.compile("ObjectInputStream"),
                Pattern.compile("\\.readObject\\s*\\("),
                Pattern.compile("XMLDecoder"),
                Pattern.compile("pickle\\.loads?\\s*\\("),
                Pattern.compile("yaml\\.(?:load|unsafe_load)\\s*\\("),
                Pattern.compile("@JsonTypeInfo"),
                Pattern.compile("enableDefaultTyping")
        ));

        map.put(SinkType.SSRF, List.of(
                Pattern.compile("new\\s+URL\\s*\\([^\"]*[+\\w]"),
                Pattern.compile("HttpURLConnection"),
                Pattern.compile("RestTemplate\\s*(?:\\(|\\.)"),
                Pattern.compile("WebClient\\.\\s*(?:create|builder)"),
                Pattern.compile("OkHttpClient"),
                Pattern.compile("requests\\.(?:get|post|put|delete|head|patch)\\s*\\(")
        ));

        map.put(SinkType.CRYPTO, List.of(
                Pattern.compile("MessageDigest\\.getInstance\\s*\\(\\s*\"(?:MD5|SHA-?1)\""),
                Pattern.compile("Cipher\\.getInstance\\s*\\(\\s*\"[^\"]*ECB"),
                Pattern.compile("(?:private|static).*(?:KEY|SECRET|PASSWORD|PASSPHRASE)\\s*=\\s*\"[^\"]+\""),
                Pattern.compile("DES(?:ede)?/"),
                Pattern.compile("new\\s+SecretKeySpec\\s*\\("),
                Pattern.compile("hashlib\\.(?:md5|sha1)\\s*\\("),
                Pattern.compile("crypto\\.createHash\\s*\\(\\s*['\"](?:md5|sha1)['\"]")
        ));

        map.put(SinkType.INSECURE_RANDOM, List.of(
                Pattern.compile("new\\s+Random\\s*\\("),
                Pattern.compile("Math\\.random\\s*\\("),
                Pattern.compile("random\\.(?:randint|random|choice|randrange)\\s*\\("),
                Pattern.compile("ThreadLocalRandom\\.current\\s*\\(")
        ));

        return Collections.unmodifiableMap(map);
    }
}
