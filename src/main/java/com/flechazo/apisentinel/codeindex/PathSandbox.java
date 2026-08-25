package com.flechazo.apisentinel.codeindex;

import com.flechazo.apisentinel.config.CodeRepo;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.InvalidPathException;
import java.nio.file.Path;
import java.util.List;

/**
 * Shared path-traversal defense for tools that let the LLM read/search files
 * by path (ReadFileTool, GrepRepoTool, AnalysisPipeline's one-hop follow).
 * Only paths that resolve (following symlinks) inside one of the configured
 * code repo roots are allowed — everything else, including the path simply
 * not existing, returns null so callers can emit a clean "not found" error
 * without leaking filesystem details.
 */
public final class PathSandbox {

    private PathSandbox() {}

    /**
     * Resolves rawPath against the configured repo roots. Accepts an absolute
     * path (as RouteEntry.sourceFile() returns) or a path relative to one of
     * the repo roots. Returns the real (symlink-resolved) path only if it is
     * actually contained within one of the repo roots; otherwise null.
     */
    public static Path resolveWithinRepos(String rawPath, List<CodeRepo> repos) {
        if (rawPath == null || rawPath.isBlank() || repos == null) return null;
        for (CodeRepo repo : repos) {
            try {
                Path root = Path.of(repo.getPath()).toRealPath();
                Path candidate = Path.of(rawPath);
                Path resolved = candidate.isAbsolute()
                        ? candidate.normalize()
                        : root.resolve(candidate).normalize();
                if (!Files.exists(resolved)) continue;
                Path real = resolved.toRealPath();
                if (real.startsWith(root)) return real;
            } catch (IOException | InvalidPathException | SecurityException ignored) {
                // try next repo root
            }
        }
        return null;
    }
}
