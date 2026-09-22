package com.flechazo.apisentinel.codeindex;

import com.flechazo.apisentinel.config.CodeRepo;

import java.io.IOException;
import java.nio.file.FileSystems;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.PathMatcher;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Shared regex-search-across-repo logic, used by GrepRepoTool (Agent mode's
 * on-demand code search) and AnalysisPipeline's one-hop follow (Pipeline mode
 * locating a class declaration by name). Reuses the same excluded-directory
 * set as CodeIndexService so generated/vendored code is skipped.
 */
public final class RepoGrepper {

    public record GrepMatch(Path file, int line, String context) {}

    /** P0-12: richer return type that lets callers tell "no matches
     *  because nothing fit the pattern" apart from "no matches because
     *  we couldn't read any of the repos". The pre-P0-12 code returned
     *  a bare {@code List<GrepMatch>} that was empty in both cases, so
     *  tools that reported {@code match_count: 0} to the LLM were
     *  silently claiming "nothing here" when the truth was "we had no
     *  access". {@code unavailableReason} is null on a healthy run
     *  (matches or no matches) and non-null only when every configured
     *  repo was unreadable. */
    public record GrepOutcome(List<GrepMatch> matches, String unavailableReason) {
        public boolean isAvailable() { return unavailableReason == null; }
        static GrepOutcome available(List<GrepMatch> matches) {
            return new GrepOutcome(matches, null);
        }
        static GrepOutcome unavailable(String reason, List<GrepMatch> partial) {
            return new GrepOutcome(partial == null ? List.of() : partial, reason);
        }
    }

    private static final Set<String> DEFAULT_EXCLUDES = Set.of(
            "node_modules", ".git", "build", "target", "dist", "__pycache__", ".venv");

    private RepoGrepper() {}

    /**
     * Walks each repo root, regex-matching each text line. Stops once
     * maxResults matches are collected across all repos combined.
     *
     * @param pathGlob optional glob filter matched against the file's path
     *                 relative to the repo root (e.g. "*.java" — rewritten to
     *                 "**\/*.java" so it still matches at any depth like the
     *                 old suffix-only behavior did; or a full glob such as
     *                 "src/**\/controller/*.java" for directory-scoped
     *                 filtering). null/blank = no filter. Malformed patterns
     *                 are treated as no filter rather than failing the search.
     */
    public static List<GrepMatch> search(List<CodeRepo> repos, Pattern pattern,
                                          String pathGlob, int maxResults, int contextLines) {
        return search(repos, pattern, pathGlob, maxResults, contextLines, false);
    }

    /**
     * @param multiline when true, matches against each file's full content
     *                  (so a pattern can span multiple lines) instead of
     *                  scanning line-by-line. Line numbers are derived from
     *                  the match's offset into the file.
     */
    public static List<GrepMatch> search(List<CodeRepo> repos, Pattern pattern,
                                          String pathGlob, int maxResults, int contextLines,
                                          boolean multiline) {
        return searchEx(repos, pattern, pathGlob, maxResults, contextLines, multiline).matches();
    }

    /** P0-12: extended form of {@link #search} that distinguishes "empty
     *  because nothing matched" from "empty because every repo was
     *  unreadable". Existing callers that only need the list can keep
     *  using {@code search()}; tool-layer callers (GrepRepoTool,
     *  McpTools) that surface the result to the LLM should prefer this
     *  overload so a permissions / mount failure doesn't get reported
     *  as {@code match_count: 0}. */
    public static GrepOutcome searchEx(List<CodeRepo> repos, Pattern pattern,
                                       String pathGlob, int maxResults, int contextLines,
                                       boolean multiline) {
        List<GrepMatch> results = new ArrayList<>();
        if (repos == null || pattern == null || maxResults <= 0) {
            return GrepOutcome.available(results);
        }
        PathMatcher matcher = buildPathMatcher(pathGlob);

        boolean anyReadable = false;
        List<String> failureReasons = new ArrayList<>();

        for (CodeRepo repo : repos) {
            if (results.size() >= maxResults) break;
            Path root;
            try {
                root = Path.of(repo.getPath());
            } catch (Exception e) {
                failureReasons.add(repo.getName() + ": invalid path");
                continue;
            }
            if (!Files.isDirectory(root)) {
                failureReasons.add(repo.getName() + ": not a directory");
                continue;
            }

            // Track readability per repo: the moment walkFileTree starts
            // and visits any entry (file OR directory), we consider the
            // repo readable — even if every individual file inside is
            // binary or filter-skipped. A repo whose root is readable
            // but happens to hold zero greppable files legitimately
            // returns 0 matches and must NOT be reported as unavailable.
            boolean[] repoReadable = {false};
            try {
                Files.walkFileTree(root, new SimpleFileVisitor<>() {
                    @Override
                    public FileVisitResult preVisitDirectory(Path dir, BasicFileAttributes attrs) {
                        repoReadable[0] = true;
                        if (results.size() >= maxResults) return FileVisitResult.TERMINATE;
                        String dirName = dir.getFileName() != null ? dir.getFileName().toString() : "";
                        if (DEFAULT_EXCLUDES.contains(dirName)) return FileVisitResult.SKIP_SUBTREE;
                        return FileVisitResult.CONTINUE;
                    }

                    @Override
                    public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) {
                        repoReadable[0] = true;
                        if (results.size() >= maxResults) return FileVisitResult.TERMINATE;
                        if (attrs.size() > 2_000_000) return FileVisitResult.CONTINUE;
                        if (matcher != null && !matcher.matches(root.relativize(file))) {
                            return FileVisitResult.CONTINUE;
                        }
                        try {
                            if (multiline) {
                                results.addAll(searchFileMultiline(file, pattern, contextLines,
                                        maxResults - results.size()));
                            } else {
                                results.addAll(searchFileByLine(file, pattern, contextLines,
                                        maxResults - results.size()));
                            }
                        } catch (IOException ignored) {
                            // unreadable/binary/non-UTF8 file — skip, keep searching
                        }
                        return FileVisitResult.CONTINUE;
                    }
                });
            } catch (IOException e) {
                failureReasons.add(repo.getName() + ": "
                        + (e.getMessage() == null ? e.getClass().getSimpleName() : e.getMessage()));
                continue;
            }
            if (repoReadable[0]) anyReadable = true;
        }

        if (!anyReadable) {
            String reason = "all_repos_unreadable: " + String.join("; ", failureReasons);
            return GrepOutcome.unavailable(reason, results);
        }
        return GrepOutcome.available(results);
    }

    /** Builds a glob PathMatcher from a user-supplied pattern, or null for no
     *  filter. A pattern with no "/" is treated as "match this filename at any
     *  depth" (prefixed with "**\/") to preserve the previous suffix-filter's
     *  semantics; a pattern already containing "/" is used as-is for real
     *  directory-scoped globbing (e.g. "src/**\/controller/*.java"). */
    private static PathMatcher buildPathMatcher(String pathGlob) {
        if (pathGlob == null || pathGlob.isBlank()) return null;
        String glob = pathGlob.contains("/") ? pathGlob : "**/" + pathGlob;
        try {
            return FileSystems.getDefault().getPathMatcher("glob:" + glob);
        } catch (Exception e) {
            return null; // malformed pattern: don't filter rather than abort the search
        }
    }

    private static List<GrepMatch> searchFileByLine(Path file, Pattern pattern,
                                                      int contextLines, int remaining) throws IOException {
        List<GrepMatch> out = new ArrayList<>();
        List<String> lines = Files.readAllLines(file);
        for (int i = 0; i < lines.size() && out.size() < remaining; i++) {
            if (!pattern.matcher(lines.get(i)).find()) continue;
            int ctxStart = Math.max(0, i - contextLines);
            int ctxEnd = Math.min(lines.size(), i + contextLines + 1);
            StringBuilder ctx = new StringBuilder();
            for (int j = ctxStart; j < ctxEnd; j++) {
                ctx.append(j + 1).append(": ").append(lines.get(j)).append('\n');
            }
            out.add(new GrepMatch(file, i + 1, ctx.toString()));
        }
        return out;
    }

    /** Matches against the whole file content so a pattern can span line
     *  boundaries; line numbers/context are derived from the match offset. */
    private static List<GrepMatch> searchFileMultiline(Path file, Pattern pattern,
                                                         int contextLines, int remaining) throws IOException {
        List<GrepMatch> out = new ArrayList<>();
        String text = Files.readString(file);
        List<String> lines = text.lines().toList();
        Matcher m = pattern.matcher(text);
        int searchFrom = 0;
        while (out.size() < remaining && m.find(searchFrom)) {
            int matchLine = countNewlinesBefore(text, m.start());
            int ctxStart = Math.max(0, matchLine - contextLines);
            int ctxEnd = Math.min(lines.size(), matchLine + contextLines + 1);
            StringBuilder ctx = new StringBuilder();
            for (int j = ctxStart; j < ctxEnd && j < lines.size(); j++) {
                ctx.append(j + 1).append(": ").append(lines.get(j)).append('\n');
            }
            out.add(new GrepMatch(file, matchLine + 1, ctx.toString()));
            searchFrom = Math.max(m.end(), m.start() + 1);
        }
        return out;
    }

    private static int countNewlinesBefore(String text, int offset) {
        int count = 0;
        for (int i = 0; i < offset && i < text.length(); i++) {
            if (text.charAt(i) == '\n') count++;
        }
        return count;
    }
}
